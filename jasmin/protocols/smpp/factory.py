# pylint: disable=W0401,W0611,W0231
import pickle
import sys
import logging
import re, random, time
import requests
from enum import Enum
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from twisted.internet.threads import deferToThread
from smpp.pdu.pdu_types import (EsmClass, EsmClassMode, EsmClassType, MessageState, AddrTon, AddrNpi)
from smpp.twisted.protocol import SMPPServerProtocol as twistedSMPPServerProtocol
from OpenSSL import SSL
from twisted.internet import defer, reactor, ssl
from twisted.internet.protocol import ClientFactory
from smpp.pdu.operations import DeliverSM
from jasmin.routing.Routables import RoutableSubmitSm
from smpp.twisted.protocol import DataHandlerResponse, SMPPSessionStates
from smpp.twisted.server import SMPPBindManager as _SMPPBindManager
from smpp.twisted.server import SMPPServerFactory as _SMPPServerFactory
from smpp.pdu.error import SMPPClientError
from smpp.pdu.pdu_types import CommandId, CommandStatus, PDURequest

from jasmin.protocols.smpp.error import (
    SubmitSmInvalidArgsError, SubmitSmWithoutDestinationAddrError, 
    InterceptorRunError, SubmitSmInterceptionError, SubmitSmInterceptionSuccess,
    SubmitSmThroughputExceededError, SubmitSmRoutingError, SubmitSmRouteNotFoundError,
    SubmitSmChargingError)
from jasmin.protocols.smpp.protocol import SMPPClientProtocol, SMPPServerProtocol
from jasmin.protocols.smpp.stats import SMPPClientStatsCollector, SMPPServerStatsCollector
from jasmin.protocols.smpp.validation import SmppsCredentialValidator

from jasmin.protocols.smpp.error import InterceptorNotSetError, InterceptorNotConnectedError

LOG_CATEGORY_CLIENT_BASE = "smpp.client"
LOG_CATEGORY_SERVER_BASE = "smpp.server"


class SmppClientIsNotConnected(Exception):
    """
    An exception that is raised when a trying to use smpp object when
    it is still None (before callbacking bind())
    """


class SMPPClientFactory(ClientFactory):
    protocol = SMPPClientProtocol

    def __init__(self, config, msgHandler=None):
        self.reconnectTimer = None
        self.smpp = None
        self.connectionRetry = True
        self.config = config

        # Setup statistics collector
        self.stats = SMPPClientStatsCollector().get(cid=self.config.id)
        self.stats.set('created_at', datetime.now())

        # Set up a dedicated logger
        self.log = logging.getLogger(LOG_CATEGORY_CLIENT_BASE + ".%s" % config.id)
        if len(self.log.handlers) != 1:
            self.log.setLevel(self.config.log_level)
            _when = self.config.log_rotate if hasattr(self.config, 'log_rotate') else 'midnight'
            if 'stdout' in self.config.log_file:
                handler = logging.StreamHandler(sys.stdout)
            else:
                handler = TimedRotatingFileHandler(filename=self.config.log_file, when=_when)
            formatter = logging.Formatter(self.config.log_format, self.config.log_date_format)
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
            self.log.propagate = False

        if msgHandler is None:
            self.msgHandler = self.msgHandlerStub
        else:
            self.msgHandler = msgHandler

    def buildProtocol(self, addr):
        """Provision protocol
        """
        proto = ClientFactory.buildProtocol(self, addr)

        # Setup logger
        proto.log = self.log

        return proto

    def getConfig(self):
        return self.config

    def msgHandlerStub(self, smpp, pdu):
        self.log.warning("msgHandlerStub: Received an unhandled message %s ...", pdu)

    def startedConnecting(self, connector):
        self.log.info("Connecting to %s ...", connector.getDestination())

    def getExitDeferred(self):
        """Get a Deferred so you can be notified on disconnect and exited
        This deferred is called once disconnection occurs without a further
        reconnection retrys
        """
        return self.exitDeferred

    def clientConnectionFailed(self, connector, reason):
        """Connection failed
        """
        self.log.error("Connection failed. Reason: %s", str(reason))

        if self.config.reconnectOnConnectionFailure and self.connectionRetry:
            self.log.info("Reconnecting after %d seconds ...",
                          self.config.reconnectOnConnectionFailureDelay)
            self.reconnectTimer = reactor.callLater(
                self.config.reconnectOnConnectionFailureDelay, self.reConnect, connector)
        else:
            self.connectDeferred.errback(reason)
            self.exitDeferred.callback(None)
            self.log.info("Exiting.")

    def clientConnectionLost(self, connector, reason):
        """Connection lost
        """
        self.log.error("Connection lost. Reason: %s", str(reason))

        if self.config.reconnectOnConnectionLoss and self.connectionRetry:
            self.log.info("Reconnecting after %d seconds ...",
                          self.config.reconnectOnConnectionLossDelay)
            self.reconnectTimer = reactor.callLater(
                self.config.reconnectOnConnectionLossDelay, self.reConnect, connector)
        else:
            self.exitDeferred.callback(None)
            self.log.info("Exiting.")

    def reConnect(self, connector=None):
        if connector is None:
            self.log.error("No connector to retry !")
        else:
            # Reset deferred if it were called before
            if self.connectDeferred.called is True:
                self.connectDeferred = defer.Deferred()
                self.connectDeferred.addCallback(self.bind)

            # And try to connect again
            connector.connect()

    def _connect(self):
        self.connectionRetry = True

        if self.config.useSSL:
            self.log.info('Establishing SSL connection to %s:%d', self.config.host, self.config.port)
            reactor.connectSSL(self.config.host, self.config.port, self, CtxFactory(self.config))
        else:
            self.log.info('Establishing TCP connection to %s:%d', self.config.host, self.config.port)
            reactor.connectTCP(self.config.host, self.config.port, self)

        self.exitDeferred = defer.Deferred()
        self.connectDeferred = defer.Deferred()
        return self.connectDeferred

    def connectAndBind(self):
        self._connect()
        self.connectDeferred.addCallback(self.bind)

        return self.connectDeferred

    # def disconnect(self):
    #     if self.smpp is not None:
    #         self.log.info('Disconnecting SMPP client')
    #         return self.smpp.unbindAndDisconnect()
    #     else:
    #         return None

    def stopConnectionRetrying(self):
        """This will stop the factory from reconnecting
        It is used whenever a service stop has been requested, the connectionRetry flag
        is reset to True upon connect() call
        """

        self.log.info('Stopped automatic connection retrying.')
        if self.reconnectTimer and self.reconnectTimer.active():
            self.reconnectTimer.cancel()
            self.reconnectTimer = None

        self.connectionRetry = False

    def disconnectAndDontRetryToConnect(self):
        self.log.info('Ordering a disconnect with no further reconnections.')
        self.stopConnectionRetrying()
        return self.disconnect()

    def bind(self, smpp):
        self.smpp = smpp

        if self.config.bindOperation == 'transceiver':
            return smpp.bindAsTransceiver()
        elif self.config.bindOperation == 'receiver':
            return smpp.bindAsReceiver()
        elif self.config.bindOperation == 'transmitter':
            return smpp.bindAsTransmitter()
        else:
            raise SMPPClientError("Invalid bind operation: %s" % self.config.bindOperation)

    def getSessionState(self):
        if self.smpp is None:
            return SMPPSessionStates.NONE
        else:
            return self.smpp.sessionState


class CtxFactory(ssl.ClientContextFactory):
    def __init__(self, config):
        self.smppConfig = config

    def getContext(self):
        self.method = SSL.SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        if self.smppConfig.SSLCertificateFile:
            ctx.use_certificate_file(self.smppConfig.SSLCertificateFile)
        return ctx

def generate_message_id():
    first_part = random.randint(1000, 9999)
    timestamp = int(time.time() * 1000)
    random_part = random.randint(1000, 9999)
    return f"smsc-{first_part}-{timestamp}-{random_part}"

_next_sequence_number = 1

def get_next_sequence_number():
    """Generate a unique sequence number for PDUs
    
    Returns a number between 1 and 0x7FFFFFFF (max 31-bit integer)
    and automatically handles rollover
    """
    global _next_sequence_number
    
    seq_num = _next_sequence_number
    
    _next_sequence_number = (_next_sequence_number + 1) & 0x7FFFFFFF
    
    if _next_sequence_number == 0:
        _next_sequence_number = 1
        
    return seq_num

class SMPPServerFactory(_SMPPServerFactory):
    protocol = SMPPServerProtocol

    def __init__(self, config, auth_portal, RouterPB=None, SMPPClientManagerPB=None,
                 interceptorpb_client=None):
        
        self.config = config
        # A dict of protocol instances for each of the current connections,
        # indexed by system_id
        self.bound_connections = {}
        self._auth_portal = auth_portal
        self.RouterPB = RouterPB
        self.SMPPClientManagerPB = SMPPClientManagerPB
        self.interceptorpb_client = interceptorpb_client

        # Setup statistics collector
        self.stats = SMPPServerStatsCollector().get(cid=self.config.id)
        self.stats.set('created_at', datetime.now())

        # Set up a dedicated logger
        self.log = logging.getLogger(LOG_CATEGORY_SERVER_BASE + ".%s" % config.id)
        if len(self.log.handlers) != 1:
            self.log.setLevel(config.log_level)
            if 'stdout' in self.config.log_file:
                handler = logging.StreamHandler(sys.stdout)
            else:
                handler = TimedRotatingFileHandler(filename=self.config.log_file, when=self.config.log_rotate)
            formatter = logging.Formatter(config.log_format, config.log_date_format)
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
            self.log.propagate = False

        self.msgHandler = self.submit_sm_event_interceptor

    def addInterceptorPBClient(self, interceptorpb_client):
        self.interceptorpb_client = interceptorpb_client

        self.log.info('Added Interceptor to SMPPServerFactory')

    def submit_sm_event_interceptor(self, system_id, *args):
        """Intercept submit_sm before handing it to self.submit_sm_event
        """

        self.log.debug('Intercepting submit_sm event for system_id: %s', system_id)

        # Args validation
        if len(args) != 2:
            self.log.error('(submit_sm_event/%s) Invalid args: %s', system_id, args)
            raise SubmitSmInvalidArgsError()
        if not isinstance(args[1], PDURequest):
            self.log.error(
                '(submit_sm_event/%s) Received an unknown object when waiting for a PDURequest: %s',
                system_id,
                args[1])
            raise SubmitSmInvalidArgsError()
        if args[1].id != CommandId.submit_sm:
            self.log.error('(submit_sm_event/%s) Received a non submit_sm command id: %s',
                           system_id, args[1].id)
            raise SubmitSmInvalidArgsError()
        if not isinstance(args[0], SMPPServerProtocol):
            self.log.error(
                '(submit_sm_event/%s) Received an unknown object when waiting for a SMPPServerProtocol: %s',
                system_id,
                args[0])
            raise SubmitSmInvalidArgsError()

        proto = args[0]
        user = proto.user
        SubmitSmPDU = args[1]

        # Update CnxStatus
        user.getCnxStatus().smpps['submit_sm_request_count'] += 1

        # Basic validation
        if len(SubmitSmPDU.params['destination_addr']) < 1 or SubmitSmPDU.params['destination_addr'] is None:
            self.log.error('(submit_sm_event/%s) SubmitSmPDU have no defined destination_addr', system_id)
            raise SubmitSmWithoutDestinationAddrError()

        # Make Credential validation
        v = SmppsCredentialValidator('Send', user, SubmitSmPDU)
        v.validate()

        # Update SubmitSmPDU by default values from user MtMessagingCredential
        SubmitSmPDU = v.updatePDUWithUserDefaults(SubmitSmPDU)
        
        # Force same default values on subPDU while multipart
        _pdu = SubmitSmPDU
        while hasattr(_pdu, 'nextPdu'):
          _pdu = _pdu.nextPdu
          _pdu = v.updatePDUWithUserDefaults(_pdu)

        if self.RouterPB is None:
            self.log.error('(submit_sm_event_interceptor/%s) RouterPB not set: submit_sm will not be routed',
                           system_id)
            return

        # Prepare for interception then routing
        routable = RoutableSubmitSm(SubmitSmPDU, user)

        # Interception inline
        # @TODO: make Interception in a thread, just like httpapi interception
        interceptor = self.RouterPB.getMTInterceptionTable().getInterceptorFor(routable)
        if interceptor is not None:
            self.log.debug("RouterPB selected %s interceptor for this SubmitSmPDU", interceptor)
            if self.interceptorpb_client is None:
                self.stats.inc('interceptor_error_count')
                self.log.error("InterceptorPB not set !")
                raise InterceptorNotSetError('InterceptorPB not set !')
            if not self.interceptorpb_client.isConnected:
                self.stats.inc('interceptor_error_count')
                self.log.error("InterceptorPB not connected !")
                raise InterceptorNotConnectedError('InterceptorPB not connected !')

            script = interceptor.getScript()
            self.log.debug("Interceptor script loaded: %s", script)

            # Run !
            d = self.interceptorpb_client.run_script(script, routable)
            d.addCallback(self.submit_sm_post_interception, system_id=system_id, proto=proto)
            d.addErrback(self.submit_sm_post_interception)
            return d
        else:
            return self.submit_sm_post_interception(routable=routable, system_id=system_id, proto=proto)

    def call_webhook(self, message_data):
        import requests

        webhook_url = "https://smppapi.wtsmessage.xyz/webhook"
        payload = {}
        for key, value in message_data.items():
            if isinstance(value, bytes):
                payload[key] = value.decode('utf-8', errors='replace')
            else:
                payload[key] = value

        try:
            response = requests.post(webhook_url, json=payload, timeout=5)
            self.log.info(f"Webhook called with status: {response.status_code}")
            return response.status_code
        except Exception as e:
            self.log.error(f"Webhook call failed: {str(e)}")
            return None

    def get_db_connection(self):
        import mysql.connector
        """Establish database connection"""
        try:
            conn = mysql.connector.connect(
                host='localhost',
                port=3306,
                user='prashanth@itsolution4india.com',
                password='Solution@97',
                database='smsc_db'
            )
            return conn
        except Exception as e:
            print(f"Database connection error: {e}")
            return None
    
    def process_pending_dlrs(self, username):
        try:
            conn = self.get_db_connection()
            if not conn:
                self.log.error("Unable to process DLRs: DB connection failed.")
                return

            cursor = conn.cursor(dictionary=True)
            query = """
                SELECT message_id, source_addr, destination_addr, status
                FROM smsc_responses
                WHERE username = %s AND dlr_status = 'pending'
            """
            cursor.execute(query, (username,))
            rows = cursor.fetchall()

            for row in rows:
                try:
                    if row['status'] is None:
                        self.log.info(f"Skipping DLR for message_id {row['message_id']} because status is NULL")
                        continue  # Skip this row, keep it pending

                    dlr_payload = {
                        'message_id': row['message_id'].encode() if isinstance(row['message_id'], str) else row['message_id'],
                        'source_addr': row['source_addr'],
                        'destination_addr': row['destination_addr'],
                        'username': username,
                        'status': row['status']
                    }
                    self.log.info(f"Processing pending DLR for message_id {row['message_id']}")
                    deferToThread(self.handle_dlr_payload, dlr_payload)

                    # Mark this DLR as processed
                    update_query = "UPDATE smsc_responses SET dlr_status = 'sent' WHERE message_id = %s"
                    cursor.execute(update_query, (row['message_id'],))
                except Exception as e:
                    self.log.error(f"Failed to handle pending DLR for message_id {row['message_id']}: {e}")

            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            self.log.error(f"Error in process_pending_dlrs: {e}")

        
    def handle_dlr_payload(self, payload):
        """Processes the DLR payload and returns a response dictionary"""
        try:
            username = payload.get('username')
            source_addr = payload.get('source_addr')
            destination_addr = payload.get('destination_addr')
            message_id = payload.get('message_id')
            status = payload.get('status', '').lower().strip()  # e.g., 'delivered'

            # Map WhatsApp webhook statuses to SMPP DLR fields
            status_map = {
                "sent":     {"stat": "DELIVRD", "err": "000", "state": MessageState.DELIVERED, "dlvrd": "001"},
                "delivered":{"stat": "DELIVRD", "err": "000", "state": MessageState.DELIVERED, "dlvrd": "001"},
                "read":     {"stat": "DELIVRD", "err": "000", "state": MessageState.DELIVERED, "dlvrd": "001"},
                "reply":    {"stat": "DELIVRD", "err": "000", "state": MessageState.DELIVERED, "dlvrd": "001"},
                "failed":   {"stat": "UNDELIV", "err": "001", "state": MessageState.UNDELIVERABLE, "dlvrd": "000"},
            }

            if status not in status_map:
                raise ValueError(f"Unknown status '{status}'")

            stat_conf = status_map[status]
            stat_str = stat_conf["stat"]
            err = stat_conf["err"]
            message_state = stat_conf["state"]
            dlvrd = stat_conf["dlvrd"]
            sub = "001"
            sub_date = datetime.now() - timedelta(minutes=2)

            short_message = (
                "id:%s sub:%s dlvrd:%s submit date:%s done date:%s stat:%s err:%s text:" % (
                    message_id,
                    sub,
                    dlvrd,
                    sub_date.strftime("%y%m%d%H%M"),
                    datetime.now().strftime("%y%m%d%H%M"),
                    stat_str,
                    err,
                )
            )

            deliver_sm = DeliverSM(
                source_addr=destination_addr,
                destination_addr=source_addr,
                esm_class=EsmClass(EsmClassMode.DEFAULT, EsmClassType.SMSC_DELIVERY_RECEIPT),
                receipted_message_id=message_id,
                short_message=short_message.encode(),
                message_state=message_state,
                source_addr_ton=AddrTon.UNKNOWN,
                source_addr_npi=AddrNpi.UNKNOWN,
                dest_addr_ton=AddrTon.UNKNOWN,
                dest_addr_npi=AddrNpi.UNKNOWN,
            )
            try:
                deliver_sm.seqNum = get_next_sequence_number()
            except Exception as e:
                self.log.error(f"Error identifying PDU type: {str(e)}")
                return {'error': f'Sequence number error: {str(e)}'}

            bind_mgr = self.bound_connections.get(username)

            # Add connection and bind information to logs for troubleshooting
            if not bind_mgr:
                self.log.warning(f"No bind manager found for user: {username}")
                return {'error': 'User not bound or unknown'}
                
            conn = bind_mgr.get_active_connection()
            if not conn:
                self.log.warning(f"No active SMPP connections found for user: {username}")
                return {'error': 'No active SMPP connection for this user'}
                
            # Use Twisted's callFromThread to safely interact with the reactor thread
            reactor.callFromThread(conn.sendPDU, deliver_sm)
            self.log.info(f"Submitted DeliverSM to {username} for status {status}")
            return {'success': True}

        except Exception as e:
            self.log.error(f"Error processing DLR payload: {e}")
            return {'error': str(e)}
    
    def send_pending_dlr(self, username):
        try:
            deferToThread(self.process_pending_dlrs, str(username))
        except Exception as e:
            self.log.error(f"Failed to call Pending DLR: {e}")
        
    
    def submit_sm_post_interception(self, *args, **kw):
        """This event handler will deliver the submit_sm to the right smppc connector.
        Note that Jasmin deliver submit_sm messages like this:
        - from httpapi to smppc (handled in jasmin.protocols.http.endpoints.send)
        - from smpps to smppc (this event handler)

        Note: This event handler MUST behave exactly like jasmin.protocols.http.endpoints.send.Send.render
        """

        try:
            # Init message id & status
            message_id = None
            status = None

            if len(args) == 1:
                self.log.error('Failed args')
                
            routable = kw['routable']
            system_id = kw['system_id']
            # proto = kw['proto']

            self.log.debug('Handling submit_sm_post_interception event for system_id: %s', system_id)

            # Get the route
            route = self.RouterPB.getMTRoutingTable().getRouteFor(routable)
            if route is None:
                self.log.error("No route matched from user %s for SubmitSmPDU: %s",
                               routable.user, routable.pdu)
                raise SubmitSmRouteNotFoundError()

            # Get connector from selected route
            self.log.debug("RouterPB selected %s route for this SubmitSmPDU", route)
            routedConnector = route.getConnector()

            if routedConnector is None:
                self.log.error("Failover route has no bound connector to handle SubmitSmPDU: %s",
                               routable.pdu)
                raise SubmitSmRoutingError()

            # QoS throttling
            if (routable.user.mt_credential.getQuota('smpps_throughput') and routable.user.mt_credential.getQuota('smpps_throughput') >= 0
                and routable.user.getCnxStatus().smpps['qos_last_submit_sm_at'] != 0):
                qos_throughput_second = 1 / float(routable.user.mt_credential.getQuota('smpps_throughput'))
                qos_throughput_ysecond_td = timedelta(microseconds=qos_throughput_second * 1000000)
                qos_delay = datetime.now() - routable.user.getCnxStatus().smpps['qos_last_submit_sm_at']
                if qos_delay < qos_throughput_ysecond_td:
                    self.log.error(
                        "QoS: submit_sm_event is faster (%s) than fixed throughput (%s) for user (%s), rejecting message.",
                        qos_delay,
                        qos_throughput_ysecond_td,
                        routable.user)

                    raise SubmitSmThroughputExceededError()
            routable.user.getCnxStatus().smpps['qos_last_submit_sm_at'] = datetime.now()
            
        except (SubmitSmInterceptionError, SubmitSmInterceptionSuccess, InterceptorRunError,
                SubmitSmRouteNotFoundError, SubmitSmThroughputExceededError, SubmitSmChargingError,
                SubmitSmRoutingError) as e:
            # Known exception handling
            status = e.status
        except Exception as e:
            # Unknown exception handling
            self.log.critical('Got an unknown exception: %s', e)
            status = CommandStatus.ESME_ROK
        else:
            self.log.debug('SubmitSmPDU sent to [cid:%s], result = %s', routedConnector.cid, message_id)

            status = CommandStatus.ESME_ROK
        finally:
        #     # Prepare message data for webhook
        #     random_num = generate_message_id()
            message_id = generate_message_id()
            if isinstance(message_id, str):
                message_id = message_id.encode()
                
            # Prepare payload for webhook
            if status == CommandStatus.ESME_ROK and message_id is not None:
                try:
                    message_data = {
                        'message_id': message_id,
                        'source_addr': routable.pdu.params['source_addr'],
                        'destination_addr': routable.pdu.params['destination_addr'],
                        'short_message': routable.pdu.params['short_message'],
                        'username': str(routable.user)
                    }
                    self.log.info(f'Calling webhook with message_id {message_id}')
                    deferToThread(self.call_webhook, message_data)
                except Exception as e:
                    self.log.error(f"Failed to call webhook: {e}")
                
                DataHandlerResponse(status=status, message_id=message_id)
                
                # try:
                #     dlr_payload = {
                #         'message_id': message_id,
                #         'source_addr': message_data['source_addr'],
                #         'destination_addr': message_data['destination_addr'],
                #         'username': message_data['username'],
                #         'status': 'sent'
                #     }
                #     self.log.info(f'Sending initial DLR (status=sent) for message_id {message_id}')
                #     deferToThread(self.handle_dlr_payload, dlr_payload)
                # except Exception as e:
                #     self.log.error(f"Failed to call DLR: {e}")
                
                # try:
                #     deferToThread(self.process_pending_dlrs, str(routable.user))
                # except Exception as e:
                #     self.log.error(f"Failed to call Pending DLR: {e}")
            return

    def buildProtocol(self, addr):
        """Provision protocol with the dedicated logger
        """
        proto = _SMPPServerFactory.buildProtocol(self, addr)

        # Setup logger
        proto.log = self.log

        return proto

    def addBoundConnection(self, connection, user):
        """
        Overloading _SMPPServerFactory to remove dependency with config.systems
        Jasmin removed systems from config as everything about credentials is
        managed through User object
        """
        system_id = connection.system_id
        self.log.debug('Adding SMPP binding for %s', system_id)
        if system_id not in self.bound_connections:
            self.bound_connections[system_id] = SMPPBindManager(user)
        self.bound_connections[system_id].addBinding(connection)
        bind_type = connection.bind_type
        self.log.info("Added %s bind for '%s'. Active binds: %s.",
                      bind_type, system_id, self.getBoundConnectionCountsStr(system_id))

    def removeConnection(self, connection):
        """
        Overloading _SMPPServerFactory to remove dependency with config.systems
        Jasmin removed systems from config as everything about credentials is
        managed through User object
        """
        if connection.system_id is None:
            self.log.debug("SMPP connection attempt failed without binding.")
        else:
            system_id = connection.system_id
            bind_type = connection.bind_type
            self.bound_connections[system_id].removeBinding(connection)
            self.log.info("Dropped %s bind for '%s'. Active binds: %s.",
                          bind_type, system_id, self.getBoundConnectionCountsStr(system_id))
            # If this is the last binding for this service then remove the BindManager
            if self.bound_connections[system_id].getBindingCount() == 0:
                self.bound_connections.pop(system_id)

    def canOpenNewConnection(self, user, bind_type):
        """
        Overloading _SMPPServerFactory to remove dependency with config.systems
        Jasmin removed systems from config as everything about credentials is
        managed through User object
        This method will check for authorization and quotas before allowing a new
        connection
        """
        # Can bind ?
        if not user.smpps_credential.getAuthorization('bind'):
            self.log.warning(
                'New bind rejected for username: "%s", reason: authorization failure.', user.username)
            return False
        # Still didnt reach max_bindings ?
        elif user.smpps_credential.getQuota('max_bindings') is not None:
            bind_count = user.getCnxStatus().smpps['bound_connections_count']['bind_transmitter']
            bind_count += user.getCnxStatus().smpps['bound_connections_count']['bind_receiver']
            bind_count += user.getCnxStatus().smpps['bound_connections_count']['bind_transceiver']
            if bind_count >= user.smpps_credential.getQuota('max_bindings'):
                self.log.warning('New bind rejected for username: "%s", reason: max_bindings limit reached.',
                                 user.username)
                return False

        return True

    # def unbindAndRemoveGateway(self, user, ban=True):
    #     """
    #     Overloading _SMPPServerFactory to remove dependency with config.systems
    #     Jasmin removed systems from config as everything about credentials is
    #     managed through User object.
    #     It's also adding a 'ban' parameter to optionally remove binding authorization
    #     for user.
    #     """
    #     if ban:
    #         user.smpps_credential.setAuthorization('bind', False)

    #     d = self.unbindGateway(user.username)
    #     return d


class SMPPBindManager(_SMPPBindManager):
    "Overloads _SMPPBindManager to add user tracking"

    def __init__(self, user):
        _SMPPBindManager.__init__(self, system_id=user.username)
        self.user = user
        self.active_connections = []

        self.user = user

    def addBinding(self, connection):
        _SMPPBindManager.addBinding(self, connection)
        self.active_connections.append(connection)

        # Update CnxStatus
        self.user.getCnxStatus().smpps['bind_count'] += 1
        self.user.getCnxStatus().smpps['bound_connections_count'][connection.bind_type.name] += 1

    def removeBinding(self, connection):
        # _SMPPBindManager.removeBinding(self, connection)
        # if connection in self.active_connections:
        #     self.active_connections.remove(connection)

        # Update CnxStatus
        self.user.getCnxStatus().smpps['unbind_count'] += 1
        self.user.getCnxStatus().smpps['bound_connections_count'][connection.bind_type.name] -= 1
        
    def get_active_connection(self):
        return self.active_connections[0] if self.active_connections else None