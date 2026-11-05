import json
import time
import ipaddress
from pathlib import Path
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from webob import Response

from . import config as controller_config
from .session_manager import SessionManager
from .event_logger import EventLogger

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "policy.json"

with POLICY_PATH.open("r", encoding="utf-8") as policy_file:
    POLICY = json.load(policy_file)

AUTH_SERVER = controller_config.HOSTS["h4"]["ip"]
WEB_SERVER = controller_config.HOSTS["h5"]["ip"]
ADMIN_SERVER = controller_config.HOSTS["h6"]["ip"]

AUTH_PORT = controller_config.AUTH_PORT
WEB_PORT = controller_config.WEB_PORT
ADMIN_PORT = controller_config.ADMIN_PORT
MANAGEMENT_IP = controller_config.MANAGEMENT_IP

CLIENTS = {
    controller_config.HOSTS[name]["ip"]
    for name in ("h1", "h2", "h3")
}
REQUIRED_SWITCH_IDS = set(controller_config.SWITCH_IDS)

ROLE_SERVICES = {
    role: [
        (service["ip"], int(service["port"]))
        for service in definition["services"]
        if service.get("protocol", "TCP").upper() == "TCP"
    ]
    for role, definition in POLICY["roles"].items()
}
if not {"user", "admin"}.issubset(ROLE_SERVICES):
    raise RuntimeError("policy.json must define user and admin roles")

MAX_SESSION_TTL = int(
    POLICY.get("security", {}).get(
        "max_session_ttl", controller_config.MAX_SESSION_TTL
    )
)
SCAN_THRESHOLD = int(
    POLICY.get("monitoring", {}).get(
        "scan_threshold", controller_config.SCAN_THRESHOLD
    )
)
SCAN_WINDOW = int(
    POLICY.get("monitoring", {}).get(
        "scan_window", controller_config.SCAN_WINDOW
    )
)
BLOCK_DURATION = int(
    POLICY.get("security", {}).get(
        "block_duration", controller_config.BLOCK_DURATION
    )
)

REST_INSTANCE = "access_control_api"

SESSION_COOKIE_BASE = 0x3000000000000000
SESSION_COOKIE_MASK = 0xffffffffffffffff
STATIC_COOKIE = 0x2000000000000000
STATIC_COOKIE_MASK = 0xffffffffffffffff
BLOCK_COOKIE_BASE = 0x4000000000000000


def session_cookie(ip):
    return SESSION_COOKIE_BASE | int(ipaddress.ip_address(ip))


class AccessControlController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(AccessControlController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.session_manager = SessionManager()
        self.event_logger = EventLogger()
        self.blocked = {}
        self.mode = "dynamic"
        self.scan_attempts = defaultdict(deque)
        self.pending_barriers = {}
        self.pending_flow_errors = {}
        kwargs["wsgi"].register(
            AccessControlAPI, {REST_INSTANCE: self}
        )

        self.maintenance_thread = hub.spawn(self.maintenance_loop)
        self.logger.info("Access Control Controller started")

    def log_event(self, event, ip=None, details=None):
        try:
            self.event_logger.log(event, ip, details)
        except Exception as error:
            self.logger.error("Could not write event log: %s", error)

    def add_flow(self, datapath, priority, match, actions,
                 hard_timeout=0, cookie=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = []
        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=int(hard_timeout)
        )
        datapath.send_msg(mod)

    def install_base_rules(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Unmatched packets are sent to the controller and dropped.
        controller_action = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.add_flow(
            datapath, 0, parser.OFPMatch(), controller_action
        )

        # Allow ARP discovery.
        self.add_flow(
            datapath, 10,
            parser.OFPMatch(eth_type=0x0806),
            [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        )

        # Allow clients to contact the authentication server.
        normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        for client_ip in CLIENTS:
            request = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6,
                ipv4_src=client_ip, ipv4_dst=AUTH_SERVER,
                tcp_dst=AUTH_PORT
            )
            reply = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6,
                ipv4_src=AUTH_SERVER, ipv4_dst=client_ip,
                tcp_src=AUTH_PORT
            )
            self.add_flow(datapath, 20, request, normal)
            self.add_flow(datapath, 20, reply, normal)

        # Permit the authentication host to reach the REST API address.
        api_request = parser.OFPMatch(
            eth_type=0x0800, ip_proto=6,
            ipv4_src=AUTH_SERVER, ipv4_dst=MANAGEMENT_IP,
            tcp_dst=controller_config.REST_API_PORT
        )
        api_reply = parser.OFPMatch(
            eth_type=0x0800, ip_proto=6,
            ipv4_src=MANAGEMENT_IP, ipv4_dst=AUTH_SERVER,
            tcp_src=controller_config.REST_API_PORT
        )

        self.add_flow(datapath, 20, api_request, normal)
        self.add_flow(datapath, 20, api_reply, normal)

        if self.mode == "static":
            self.install_static_rules(datapath)

    def delete_cookie(self, datapath, cookie, mask):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            cookie=cookie,
            cookie_mask=mask,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        ))

    def required_datapaths(self):
        datapaths = dict(self.datapaths)
        missing = REQUIRED_SWITCH_IDS.difference(datapaths)
        if missing:
            raise RuntimeError(
                "Required switches are not connected: {}".format(
                    sorted(missing)
                )
            )
        return {switch_id: datapaths[switch_id]
                for switch_id in sorted(REQUIRED_SWITCH_IDS)}

    def cookie_delete_mod(self, datapath, cookie, mask):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        return parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            cookie=cookie,
            cookie_mask=mask,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )

    def remove_ip_flows(self, ip, confirm=False, datapaths=None):
        cookie = session_cookie(ip)
        targets = datapaths or dict(self.datapaths)
        for datapath in targets.values():
            delete_mod = self.cookie_delete_mod(
                datapath, cookie, SESSION_COOKIE_MASK
            )
            if confirm:
                self.send_flow_batch(datapath, [delete_mod])
            else:
                datapath.send_msg(delete_mod)

    def static_flow_mods(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        normal = [
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]

        # Static baseline: h1 can access web; h2 can access web and admin.
        rules = [
            ("10.0.0.1", WEB_SERVER, WEB_PORT),
            ("10.0.0.2", WEB_SERVER, WEB_PORT),
            ("10.0.0.2", ADMIN_SERVER, ADMIN_PORT)
        ]
        flow_mods = []
        for client_ip, server_ip, port in rules:
            matches = [
                parser.OFPMatch(
                    eth_type=0x0800, ip_proto=6,
                    ipv4_src=client_ip, ipv4_dst=server_ip,
                    tcp_dst=port
                ),
                parser.OFPMatch(
                    eth_type=0x0800, ip_proto=6,
                    ipv4_src=server_ip, ipv4_dst=client_ip,
                    tcp_src=port
                )
            ]
            for match in matches:
                instructions = [
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, normal
                    )
                ]
                flow_mods.append(parser.OFPFlowMod(
                    datapath=datapath,
                    cookie=STATIC_COOKIE,
                    priority=30,
                    match=match,
                    instructions=instructions
                ))
        return flow_mods

    def install_static_rules(self, datapath):
        for flow_mod in self.static_flow_mods(datapath):
            datapath.send_msg(flow_mod)

    def set_mode(self, mode):
        if mode not in ("static", "dynamic"):
            raise ValueError("Mode must be static or dynamic")
        if mode == self.mode:
            return {"mode": self.mode, "message": "Already active"}

        datapaths = self.required_datapaths()
        try:
            for datapath in datapaths.values():
                flow_mods = [
                    self.cookie_delete_mod(
                        datapath, STATIC_COOKIE, STATIC_COOKIE_MASK
                    ),
                    self.cookie_delete_mod(
                        datapath, SESSION_COOKIE_BASE,
                        0xf000000000000000
                    )
                ]
                if mode == "static":
                    flow_mods.extend(self.static_flow_mods(datapath))
                self.send_flow_batch(datapath, flow_mods)
        except Exception:
            # A failed mode transition must not leave stale allow rules behind.
            for datapath in datapaths.values():
                try:
                    self.send_flow_batch(datapath, [
                        self.cookie_delete_mod(
                            datapath, STATIC_COOKIE, STATIC_COOKIE_MASK
                        ),
                        self.cookie_delete_mod(
                            datapath, SESSION_COOKIE_BASE,
                            0xf000000000000000
                        )
                    ])
                except Exception as cleanup_error:
                    self.logger.error(
                        "Mode rollback failed on switch %s: %s",
                        datapath.id, cleanup_error
                    )
            for ip in list(self.session_manager.get_active_sessions()):
                self.session_manager.revoke_session(ip)
            self.mode = "dynamic"
            self.log_event("MODE_CHANGE_FAILED", details={"requested": mode})
            raise

        for ip in list(self.session_manager.get_active_sessions()):
            self.session_manager.revoke_session(ip)
        self.mode = mode
        self.log_event("MODE_CHANGED", details={"mode": mode})
        return {
            "mode": self.mode,
            "message": "Mode changed",
            "switches_confirmed": sorted(datapaths)
        }

    def send_flow_batch(self, datapath, flow_mods, timeout=5):
        waiter = hub.Event()
        error_state = {"error": None}
        error_keys = []

        for mod in flow_mods:
            datapath.set_xid(mod)
            key = (datapath.id, mod.xid)
            self.pending_flow_errors[key] = error_state
            error_keys.append(key)

        parser = datapath.ofproto_parser
        barrier = parser.OFPBarrierRequest(datapath)
        datapath.set_xid(barrier)
        barrier_key = (datapath.id, barrier.xid)
        self.pending_barriers[barrier_key] = waiter

        try:
            for mod in flow_mods:
                datapath.send_msg(mod)

            datapath.send_msg(barrier)
            waiter.wait(timeout)

            if not waiter.is_set():
                raise RuntimeError(
                    "Timed out waiting for switch {} confirmation".format(
                        datapath.id
                    )
                )

            if error_state["error"]:
                raise RuntimeError(
                    "Switch {} rejected a flow: {}".format(
                        datapath.id, error_state["error"]
                    )
                )
        finally:
            self.pending_barriers.pop(barrier_key, None)
            for key in error_keys:
                self.pending_flow_errors.pop(key, None)

    def install_session(self, ip, role, ttl):
        if self.mode != "dynamic":
            raise ValueError("Session grants require dynamic mode")
        if ip not in CLIENTS:
            raise ValueError("Unknown client IP")
        if role not in ROLE_SERVICES:
            raise ValueError("Role is not defined in policy.json")
        if not isinstance(ttl, int) or ttl <= 0 or ttl > MAX_SESSION_TTL:
            raise ValueError(
                "TTL must be between 1 and {} seconds".format(
                    MAX_SESSION_TTL
                )
            )
        if ip in self.blocked:
            raise ValueError("Client is currently blocked")

        datapaths = self.required_datapaths()
        services = ROLE_SERVICES[role]
        if not services:
            raise ValueError("Role has no TCP services in policy.json")

        cookie = session_cookie(ip)
        try:
            # Remove stale rules and confirm deletion before replacing a session.
            self.remove_ip_flows(ip, confirm=True, datapaths=datapaths)

            for switch_id, datapath in datapaths.items():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                flow_mods = []

                for server_ip, port in services:
                    matches = [
                        parser.OFPMatch(
                            eth_type=0x0800, ip_proto=6,
                            ipv4_src=ip, ipv4_dst=server_ip,
                            tcp_dst=port
                        ),
                        parser.OFPMatch(
                            eth_type=0x0800, ip_proto=6,
                            ipv4_src=server_ip, ipv4_dst=ip,
                            tcp_src=port
                        )
                    ]
                    for match in matches:
                        instructions = [
                            parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS, normal
                            )
                        ]
                        flow_mods.append(parser.OFPFlowMod(
                            datapath=datapath,
                            cookie=cookie,
                            priority=30,
                            match=match,
                            instructions=instructions,
                            hard_timeout=int(ttl)
                        ))

                self.send_flow_batch(datapath, flow_mods)

        except Exception:
            # Best-effort cleanup; do not create an authenticated session on failure.
            try:
                self.remove_ip_flows(
                    ip, confirm=True, datapaths=datapaths
                )
            except Exception as cleanup_error:
                self.logger.error(
                    "Could not fully clean failed grant for %s: %s",
                    ip, cleanup_error
                )
            self.session_manager.revoke_session(ip)
            raise

        session = self.session_manager.create_session(
            ip, role, services, ttl
        )
        self.log_event("SESSION_GRANTED", ip, {
            "role": role, "ttl": ttl, "services": services
        })
        return {
            "action": "granted", "ip": ip, "role": role,
            "services": services, "expires_at": session["expires_at"]
        }

    def revoke(self, ip):
        if ip not in CLIENTS:
            raise ValueError("Unknown client IP")

        datapaths = self.required_datapaths()
        self.remove_ip_flows(ip, confirm=True, datapaths=datapaths)
        self.session_manager.revoke_session(ip)
        self.log_event("SESSION_REVOKED", ip)
        return {"action": "revoked", "ip": ip, "switches_confirmed": sorted(datapaths)}

    def block(self, ip, duration, reason):
        if ip not in CLIENTS:
            raise ValueError("Unknown client IP")
        if not isinstance(duration, int) or duration <= 0:
            raise ValueError("Block duration must be a positive integer")

        datapaths = self.required_datapaths()
        block_cookie = BLOCK_COOKIE_BASE | int(ipaddress.ip_address(ip))
        # Mark blocked before installing rules so repeated probes do not race.
        self.blocked[ip] = {
            "until": time.time() + duration,
            "reason": reason
        }
        self.session_manager.revoke_session(ip)

        try:
            for switch_id, datapath in datapaths.items():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                drop_match = parser.OFPMatch(
                    eth_type=0x0800, ipv4_src=ip
                )
                flow_mods = [
                    self.cookie_delete_mod(
                        datapath, session_cookie(ip), SESSION_COOKIE_MASK
                    ),
                    self.cookie_delete_mod(
                        datapath, block_cookie, SESSION_COOKIE_MASK
                    ),
                    parser.OFPFlowMod(
                        datapath=datapath,
                        cookie=block_cookie,
                        priority=50,
                        match=drop_match,
                        instructions=[],
                        hard_timeout=int(duration)
                    )
                ]
                self.send_flow_batch(datapath, flow_mods)
        except Exception:
            self.log_event("BLOCK_INSTALL_FAILED", ip, {
                "duration": duration, "reason": reason
            })
            raise

        self.log_event("CLIENT_BLOCKED", ip, {
            "duration": duration, "reason": reason
        })
        return {
            "action": "blocked", "ip": ip,
            "duration": duration, "reason": reason,
            "switches_confirmed": sorted(datapaths)
        }

    def record_scan_attempt(self, ip):
        now = time.time()
        attempts = self.scan_attempts[ip]
        attempts.append(now)

        while attempts and now - attempts[0] > SCAN_WINDOW:
            attempts.popleft()

        if len(attempts) >= SCAN_THRESHOLD and ip not in self.blocked:
            self.log_event("SCAN_DETECTED", ip, {
                "attempts": len(attempts),
                "window_seconds": SCAN_WINDOW
            })
            self.block(ip, BLOCK_DURATION, "Excessive connection attempts")
            attempts.clear()

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def flow_error_handler(self, ev):
        msg = ev.msg
        pending = self.pending_flow_errors.get(
            (msg.datapath.id, msg.xid)
        )
        if pending is not None:
            pending["error"] = (
                "OpenFlow error type={}, code={}".format(
                    msg.type, msg.code
                )
            )

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        msg = ev.msg
        waiter = self.pending_barriers.get(
            (msg.datapath.id, msg.xid)
        )
        if waiter is not None:
            waiter.set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip_header = pkt.get_protocol(ipv4.ipv4)
        tcp_header = pkt.get_protocol(tcp.tcp)

        if ip_header and tcp_header and ip_header.src in CLIENTS:
            if ip_header.src not in self.blocked:
                self.record_scan_attempt(ip_header.src)
        # No packet-out is sent: unmatched traffic remains denied.

    def maintenance_loop(self):
        while True:
            try:
                with self.session_manager.lock:
                    previous = set(self.session_manager.sessions.keys())

                active = self.session_manager.get_active_sessions()
                expired = previous - set(active.keys())

                for ip in expired:
                    self.remove_ip_flows(ip)
                    self.log_event("SESSION_EXPIRED", ip)

                now = time.time()
                for ip, details in list(self.blocked.items()):
                    if details["until"] <= now:
                        del self.blocked[ip]
                        self.log_event("CLIENT_UNBLOCKED", ip)

                for ip, attempts in list(self.scan_attempts.items()):
                    while attempts and now - attempts[0] > SCAN_WINDOW:
                        attempts.popleft()
                    if not attempts:
                        self.scan_attempts.pop(ip, None)

            except Exception as error:
                self.logger.error("Maintenance error: %s", error)

            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.install_base_rules(datapath)
        self.log_event("SWITCH_CONNECTED", details={
            "switch_id": datapath.id
        })
        self.logger.info(
            "Base access rules installed on switch %s", datapath.id
        )

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.log_event("SWITCH_DISCONNECTED", details={
                "switch_id": datapath.id
            })


class AccessControlAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(AccessControlAPI, self).__init__(
            req, link, data, **config
        )
        self.controller = data[REST_INSTANCE]

    def respond(self, result, status=200):
        return Response(
            content_type="application/json",
            body=json.dumps(result).encode("utf-8"),
            status=status
        )

    def authorize_management_access(self, req):
        # The API listener binds before Mininet creates cHost, so restrict
        # requests at the application layer as well as with OpenFlow rules.
        remote_ip = req.remote_addr
        trusted_sources = {
            AUTH_SERVER, MANAGEMENT_IP, "127.0.0.1", "::1"
        }
        if remote_ip not in trusted_sources:
            self.controller.log_event(
                "REST_ACCESS_DENIED",
                remote_ip,
                {"path": req.path}
            )
            return self.respond({"error": "forbidden"}, 403)
        return None

    @route("grant", "/acl/grant", methods=["POST"])
    def grant(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        try:
            body = req.json
            result = self.controller.install_session(
                body["ip"], body["role"],
                int(body.get("ttl", 60))
            )
            return self.respond(result)
        except Exception as error:
            return self.respond({"error": str(error)}, 400)

    @route("revoke", "/acl/revoke", methods=["POST"])
    def revoke(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        try:
            return self.respond(self.controller.revoke(req.json["ip"]))
        except Exception as error:
            return self.respond({"error": str(error)}, 400)

    @route("block", "/acl/block", methods=["POST"])
    def block(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        try:
            body = req.json
            result = self.controller.block(
                body["ip"], int(body.get("duration", 60)),
                body.get("reason", "Policy violation")
            )
            return self.respond(result)
        except Exception as error:
            return self.respond({"error": str(error)}, 400)

    @route("mode", "/acl/mode", methods=["POST"])
    def mode(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        try:
            return self.respond(
                self.controller.set_mode(req.json["mode"])
            )
        except Exception as error:
            return self.respond({"error": str(error)}, 400)

    @route("sessions", "/acl/sessions", methods=["GET"])
    def sessions(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        return self.respond(
            self.controller.session_manager.get_active_sessions()
        )

    @route("logs", "/acl/log", methods=["GET"])
    def logs(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        try:
            return self.respond(self.controller.event_logger.read_all())
        except Exception as error:
            return self.respond({"error": str(error)}, 500)

    @route("stats", "/acl/stats", methods=["GET"])
    def stats(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        active = self.controller.session_manager.get_active_sessions()
        return self.respond({
            "mode": self.controller.mode,
            "connected_switches": len(self.controller.datapaths),
            "active_sessions": len(active),
            "blocked_clients": len(self.controller.blocked),
            "monitored_clients": len(self.controller.scan_attempts),
            "switch_ids": sorted(self.controller.datapaths.keys())
        })

    @route("topology", "/acl/topology", methods=["GET"])
    def topology(self, req, **kwargs):
        denied = self.authorize_management_access(req)
        if denied is not None:
            return denied
        return self.respond({
            "switches": ["s1", "s2", "s3"],
            "hosts": {
                "h1": "10.0.0.1", "h2": "10.0.0.2",
                "h3": "10.0.0.3", "h4": "10.0.0.4",
                "h5": WEB_SERVER, "h6": ADMIN_SERVER,
                "cHost": MANAGEMENT_IP
            },
            "links": [
                ["h1", "s1"], ["h2", "s1"], ["h3", "s1"],
                ["s1", "s2"], ["s2", "s3"],
                ["s3", "h4"], ["s3", "h5"], ["s3", "h6"],
                ["s3", "cHost"]
            ]
        })
