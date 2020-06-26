//
//  URLEndpontListenerTest.swift
//  CouchbaseLite
//
//  Copyright (c) 2020 Couchbase, Inc. All rights reserved.
//
//  Licensed under the Couchbase License Agreement (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  https://info.couchbase.com/rs/302-GJY-034/images/2017-10-30_License_Agreement.pdf
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

// tag::listener[]

import XCTest
@testable import CouchbaseLiteSwift

@available(macOS 10.12, iOS 10.0, *)
class URLEndpontListenerTest: ReplicatorTest {
    let wsPort: UInt16 = 4984
    let wssPort: UInt16 = 4985
    let serverCertLabel = "CBL-Server-Cert"
    let clientCertLabel = "CBL-Client-Cert"

    var listener: URLEndpointListener?

    @discardableResult
    func listen() throws -> URLEndpointListener {
        return try listen(tls: true, auth: nil)
    }

    @discardableResult
    func listen(tls: Bool) throws -> URLEndpointListener {
        return try! listen(tls: tls, auth: nil)
    }

    @discardableResult
    // tag::xctListener-start-func[]
    func listen(tls: Bool, auth: ListenerAuthenticator?) throws -> URLEndpointListener {
        // Stop:
        if let listener = self.listener {
            listener.stop()
        }

        // Listener:
    // tag::xctListener-start[]
    // tag::xctListener-config[]
    //  ... fragment preceded by other user code, including
    //  ... Couchbase Lite Database initialization that returns `_userDB`

    guard let db = _userDb else {
      throw print("DatabaseNotInitialized")
      // ... take appropriate actions
    }
    var listener: URLEndpointListener?
    let config = URLEndpointListenerConfiguration.init(database: db)
    config.port = tls ? wssPort : wsPort
    config.disableTLS = !tls
    config.authenticator = auth
    self.listener = URLEndpointListener.init(config: config)
//  ... fragment followed by other user code
    // end::xctListener-config[]

        // Start:
        try self.listener!.start()
    // end::xctListener-start[]

        return self.listener!
    }
    // end::xctListener-start-func[]

    func stopListen() throws {
        if let listener = self.listener {
            try stopListener(listener: listener)
        }
    }

    func stopListener(listener: URLEndpointListener) throws {
    // tag::xctListener-stop-func[]
    var listener: URLEndpointListener?
        let identity = listener.tlsIdentity
        listener.stop()
        if let id = identity {
            try id.deleteFromKeyChain()
    // end::xctListener-stop-func[]
        }
    }

    func cleanUpIdentities() throws {
// tag::xctListener-delete-anon-ids[]
        try URLEndpointListener.deleteAnonymousIdentities()
// end::xctListener-delete-anon-ids[]
    }

    override func setUp() {
        super.setUp()
        try! cleanUpIdentities()
    }

    override func tearDown() {
        try! stopListen()
        try! cleanUpIdentities()
        super.tearDown()
    }

    func testTLSIdentity() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        // Disabled TLS:
        var config = URLEndpointListenerConfiguration.init(database: self.oDB)
        config.disableTLS = true
        var listener = URLEndpointListener.init(config: config)
        XCTAssertNil(listener.tlsIdentity)

        try listener.start()
        XCTAssertNil(listener.tlsIdentity)
        try stopListener(listener: listener)
        XCTAssertNil(listener.tlsIdentity)

// tag::xctListener-auth-tls-tlsidentity-anon[]
        // Anonymous Identity:

        config = URLEndpointListenerConfiguration.init(database: self.oDB)
        listener = URLEndpointListener.init(config: config)
        XCTAssertNil(listener.tlsIdentity)

        try listener.start()
        XCTAssertNotNil(listener.tlsIdentity)
        try stopListener(listener: listener)
        XCTAssertNil(listener.tlsIdentity)

// end::xctListener-auth-tls-tlsidentity-anon[]

// tag::xctListener-auth-tls-tlsidentity-ca[]
        // User Identity:
        try TLSIdentity.deleteIdentity(withLabel: serverCertLabel);
        let attrs = [certAttrCommonName: "CBL-Server"]
        let identity = try TLSIdentity.createIdentity(forServer: true,
                                                      attributes: attrs,
                                                      expiration: nil,
                                                      label: serverCertLabel)
        config = URLEndpointListenerConfiguration.init(database: self.oDB)
        config.tlsIdentity = identity
        listener = URLEndpointListener.init(config: config)
        var(listener.tlsIdentity)

        try listener.start()
        XCTAssertNotNil(listener.tlsIdentity)
        XCTAssert(identity === listener.tlsIdentity!)
        try stopListener(listener: listener)
        XCTAssertNil(listener.tlsIdentity)
// end::xctListener-auth-tls-tlsidentity-ca[]
    }

    func testPasswordAuthenticator() throws {
// tag::xctListener-auth-basic-pwd-full[]
        // Listener:
// tag::xctListener-auth-basic-pwd[]
        let listenerAuth = ListenerPasswordAuthenticator.init {
            (username, password) -> Bool in
            return (username as NSString).isEqual(to: "daniel") &&
                   (password as NSString).isEqual(to: "123")
        }
        let listener = try listen(tls: false, auth: listenerAuth)

        auth = BasicAuthenticator.init(username: "daniel", password: "123")
        self.run(target: listener.localURLEndpoint, type: .pushAndPull,    continuous: false,
                 auth: auth)
// end::xctListener-auth-basic-pwd[]

        // Replicator - No Authenticator:
        self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                 auth: nil, expectedError: CBLErrorHTTPAuthRequired)

        // Replicator - Wrong Credentials:
        var auth = BasicAuthenticator.init(username: "daniel", password: "456")
        self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                 auth: auth, expectedError: CBLErrorHTTPAuthRequired)


        // Cleanup:
        try stopListen()
    }
// end::xctListener-auth-basic-pwd-full[]

    func testClientCertAuthenticatorWithClosure() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        // Listener:
        let listenerAuth = ListenerCertificateAuthenticator.init { (certs) -> Bool in
            XCTAssertEqual(certs.count, 1)
            var commongName: CFString?
            let status = SecCertificateCopyCommonName(certs[0], &commongName)
            XCTAssertEqual(status, errSecSuccess)
            XCTAssertNotNil(commongName)
            XCTAssertEqual((commongName! as String), "daniel")
            return true
        }
        let listener = try listen(tls: true, auth: listenerAuth)
        XCTAssertNotNil(listener.tlsIdentity)
        XCTAssertEqual(listener.tlsIdentity!.certs.count, 1)

        // Cleanup:
        try TLSIdentity.deleteIdentity(withLabel: clientCertLabel)

        // Create client identity:
        let attrs = [certAttrCommonName: "daniel"]
        let identity = try TLSIdentity.createIdentity(forServer: false, attributes: attrs, expiration: nil, label: clientCertLabel)

        // Replicator:
        let auth = ClientCertificateAuthenticator.init(identity: identity)
        let serverCert = listener.tlsIdentity!.certs[0]
        self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false, auth: auth, serverCert: serverCert)

        // Cleanup:
        try TLSIdentity.deleteIdentity(withLabel: clientCertLabel)
        try stopListen()
    }

    func testClientCertAuthenticatorWithRootCerts() throws {
        if !self.keyChainAccessAllowed {
            return
        }

// tag::xctListener-auth-tls-CCA-Root-full[]
// tag::xctListener-auth-tls-CCA-Root[]
        // Root Cert:
        let rootCertData = try dataFromResource(name: "identity/client-ca", ofType: "der")
        let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!

        // Listener:
        let listenerAuth = ListenerCertificateAuthenticator.init(rootCerts: [rootCert])
        let listener = try listen(tls: true, auth: listenerAuth)
// end::xctListener-auth-tls-CCA-Root[]

        // Cleanup:
        try TLSIdentity.deleteIdentity(withLabel: clientCertLabel)

        // Create client identity:
        let clientCertData = try dataFromResource(name: "identity/client", ofType: "p12")
        let identity = try TLSIdentity.importIdentity(withData: clientCertData, password: "123", label: clientCertLabel)

        // Replicator:
        let auth = ClientCertificateAuthenticator.init(identity: identity)
        let serverCert = listener.tlsIdentity!.certs[0]

        self.ignoreException {
            self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false, auth: auth, serverCert: serverCert)
// end::xctListener-auth-tls-CCA-Root-full[]
        }

        // Cleanup:
        try TLSIdentity.deleteIdentity(withLabel: clientCertLabel)
        try stopListen()
    }

    func testServerCertVerificationModeSelfSignedCert() throws {
        if !self.keyChainAccessAllowed {
            return
        }
// tag::xctListener-auth-tls-self-signed-full[]
// tag::xctListener-auth-tls-self-signed[]
        // Listener:
        let listener = try listen(tls: true)
        XCTAssertNotNil(listener.tlsIdentity)
        XCTAssertEqual(listener.tlsIdentity!.certs.count, 1)


        // Replicator - Success:
        self.ignoreException {
            self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                     serverCertVerifyMode: .selfSignedCert, serverCert: nil)
        }
// end::xctListener-auth-tls-self-signed[]
        // Replicator - TLS Error:
        self.ignoreException {
            self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                     serverCertVerifyMode: .caCert, serverCert: nil, expectedError: CBLErrorTLSCertUnknownRoot)
        }

        // Cleanup
        try stopListen()
// end::xctListener-auth-tls-self-signed-full[]
    }

// tag::xctListener-auth-tls-ca-cert-full[]
    func testServerCertVerificationModeCACert() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        // Listener:
// tag::xctListener-auth-tls-ca-cert[]
        let listener = try listen(tls: true)
        XCTAssertNotNil(listener.tlsIdentity)
        XCTAssertEqual(listener.tlsIdentity!.certs.count, 1)

        // Replicator - Success:
        self.ignoreException {
            let serverCert = listener.tlsIdentity!.certs[0]
            self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                     serverCertVerifyMode: .caCert, serverCert: serverCert)
        }
// end::xctListener-auth-tls-ca-cert[]

        // Replicator - TLS Error:
        self.ignoreException {
            self.run(target: listener.localURLEndpoint, type: .pushAndPull, continuous: false,
                     serverCertVerifyMode: .caCert, serverCert: nil, expectedError: CBLErrorTLSCertUnknownRoot)
        }

        // Cleanup
        try stopListen()
    }

    func testPort() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        let config = URLEndpointListenerConfiguration(database: self.oDB)
        config.port = wsPort
        self.listener = URLEndpointListener(config: config)
        XCTAssertNil(self.listener!.port)

        // Start:
        try self.listener!.start()
        XCTAssertEqual(self.listener!.port, wsPort)

        try stopListen()
        XCTAssertNil(self.listener!.port)
    }

    func testEmptyPort() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        let config = URLEndpointListenerConfiguration(database: self.oDB)
        self.listener = URLEndpointListener(config: config)
        XCTAssertNil(self.listener!.port)

        // Start:
        try self.listener!.start()
        XCTAssertNotEqual(self.listener!.port, 0)

        try stopListen()
        XCTAssertNil(self.listener!.port)
    }

    func testBusyPort() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        try listen()

        let config = URLEndpointListenerConfiguration(database: self.oDB)
        config.port = self.listener!.port
        let listener2 = URLEndpointListener(config: config)

        expectError(domain: NSPOSIXErrorDomain, code: Int(EADDRINUSE)) {
            try listener2.start()
        }
    }

    func testURLs() throws {
        if !self.keyChainAccessAllowed {
            return
        }

        let config = URLEndpointListenerConfiguration(database: self.oDB)
        config.port = wsPort
        self.listener = URLEndpointListener(config: config)
        XCTAssertNil(self.listener!.urls)

        // Start:
        try self.listener!.start()
        XCTAssert(self.listener!.urls?.count != 0)

        try stopListen()
        XCTAssertNil(self.listener!.urls)
    }

    func testConnectionStatus() throws {
// tag::xctListener-status-check-full[]
        if !self.keyChainAccessAllowed {
            return
        }

        let config = URLEndpointListenerConfiguration(database: self.oDB)
        config.port = wsPort
        config.disableTLS = true
        self.listener = URLEndpointListener(config: config)
        XCTAssertEqual(self.listener!.status.connectionCount, 0)
        XCTAssertEqual(self.listener!.status.activeConnectionCount, 0)

        // Start:
        try self.listener!.start()
        XCTAssertEqual(self.listener!.status.connectionCount, 0)
        XCTAssertEqual(self.listener!.status.activeConnectionCount, 0)

        try generateDocument(withID: "doc-1")
        let rConfig = self.config(target: self.listener!.localURLEndpoint,
                                 type: .pushAndPull, continuous: false, auth: nil,
                                 serverCertVerifyMode: .caCert, serverCert: nil)
        var maxConnectionCount: UInt64 = 0, maxActiveCount:UInt64 = 0
        run(config: rConfig, reset: false, expectedError: nil) { (replicator) in
            replicator.addChangeListener { (change) in
                maxConnectionCount = max(self.listener!.status.connectionCount, maxConnectionCount)
                maxActiveCount = max(self.listener!.status.activeConnectionCount, maxActiveCount)
            }
        }
        XCTAssertEqual(maxConnectionCount, 1)
        XCTAssertEqual(maxActiveCount, 1)
        XCTAssertEqual(self.oDB.count, 1)

        try stopListen()
        XCTAssertEqual(self.listener!.status.connectionCount, 0)
        XCTAssertEqual(self.listener!.status.activeConnectionCount, 0)
    }
// end::xctListener-status-check-full[]

}

@available(macOS 10.12, iOS 10.0, *)
extension URLEndpointListener {
    var localURL: URL {
        assert(self.port != nil && self.port! > UInt16(0))
        var comps = URLComponents()
        comps.scheme = self.config.disableTLS ? "ws" : "wss"
        comps.host = "localhost"
        comps.port = Int(self.port!)
        comps.path = "/\(self.config.database.name)"
        return comps.url!
    }

    var localURLEndpoint: URLEndpoint {
        return URLEndpoint.init(url: self.localURL)
    }
}
// end::start-replication[]

// tag::xctListener-auth-password-basic[]
listenerConfig.authenticator = ListenerPasswordAuthenticator.init {
            (username, password) -> Bool in
    if (self._allowListedUsers.contains(["password" : password, "name":username])) {
        return true
    }
    return false
// end::xctListener-auth-password-basic[]

// tag::xctListener-auth-cert-roots[]
let rootCertData = try dataFromResource(name: "identity/client-ca", ofType: "der")
let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
let listenerAuth = ListenerCertificateAuthenticator.init(rootCerts: [rootCert])
let listener = try listen(tls: true, auth: listenerAuth)// end::xctListener-auth-cert-roots[]

// tag::xctListener-auth-cert-auth[]
let listenerAuth = ListenerCertificateAuthenticator.init { (certs) -> Bool in
    XCTAssertEqual(certs.count, 1)
    var commongName: CFString?
    let status = SecCertificateCopyCommonName(certs[0], &commongName)
    XCTAssertEqual(status, errSecSuccess)
    XCTAssertNotNil(commongName)
    XCTAssertEqual((commongName! as String), "daniel")
    return true
}
// end::xctListener-auth-cert-auth[]

// tag::xctListener-config-basic-auth[]
let listenerConfig = URLEndpointListenerConfiguration(database: db)
listenerConfig.disableTLS  = true // Use with anonymous self signed cert
listenerConfig.enableDeltaSync = true
listenerConfig.tlsIdentity = nil

listenerConfig.authenticator = ListenerPasswordAuthenticator.init {
            (username, password) -> Bool in
    if (self._whitelistedUsers.contains(["password" : password, "name":username])) {
        return true
    }
    return false
        }

_websocketListener = URLEndpointListener(config: listenerConfig)
// end::xctListener-config-basic-auth[]





// tag::replication-start-func[]
    func startP2PReplicationWithUserDatabaseToRemotePeer(_ peer:PeerHost, handler:@escaping(_ status:PeerConnectionStatus)->Void) throws{
        print("\(#function) with ws://\(peer)/\(kUserDBName)")
        guard let userDb = _userDb else {
          throw print("DatabaseNotInitialized")
          // ... take appropriate actions
        }
        guard let user = self.currentUserCredentials?.user, let password = self.currentUserCredentials?.password else {
          throw print("UserCredentialsNotProvided")
          // ... take appropriate actions
        }

// tag::replicator-start-func-config-init[]
        var replicatorForUserDb = _replicatorsToPeers[peer]

        if replicatorForUserDb == nil {
            // Start replicator to connect to the URLListenerEndpoint
            guard let targetUrl = URL(string: "ws://\(peer)/\(kUserDBName)") else {
                throw print("URLInvalid")
                // ... take appropriate actions
            }


            let config = ReplicatorConfiguration.init(database: userDb, target: URLEndpoint.init(url:targetUrl)) //<1>
// end::replicator-start-func-config-init[]

// tag::replicator-start-func-config-more[]

            config.replicatorType = .pushAndPull // <2>
            config.continuous =  true // <3>

// end::replicator-start-func-config-more[]

// tag::replicator-start-func-config-auth[]

            config.serverCertificateVerificationMode = .selfSignedCert
            let authenticator = BasicAuthenticator(username: user, password: password)
            config.authenticator = authenticator
// end::replicator-start-func-config-auth[]

// tag::replicator-start-func-repl-init[]
replicatorForUserDb = Replicator.init(config: config)
_replicatorsToPeers[peer] = replicatorForUserDb
// end::replicator-start-func-repl-init[]
          }


// tag::replicator-start-func-repl-start[]
if let pushPullReplListenerForUserDb = registerForEventsForReplicator(replicatorForUserDb,handler:handler) {
    _replicatorListenersToPeers[peer] = pushPullReplListenerForUserDb

}
replicatorForUserDb?.start()
handler(PeerConnectionStatus.Connecting)
// end::replicator-start-func-repl-start[]

      }
// end::replication-start-func[]


// tag::replicator-register-for-events[]
fileprivate func registerForEventsForReplicator(_ replicator:Replicator?,
  handler:@escaping(_ status:PeerConnectionStatus)->Void )->ListenerToken? {
    let pushPullReplListenerForUserDb = replicator?.addChangeListener({ (change) in

      let s = change.status
      if s.error != nil {
          handler(PeerConnectionStatus.Error)
          return
      }

      switch s.activity {
      case .connecting:
          print("Replicator Connecting to Peer")
          handler(PeerConnectionStatus.Connecting)
      case .idle:
          print("Replicator in Idle state")
          handler(PeerConnectionStatus.Connected)
      case .busy:
          print("Replicator in busy state")
          handler(PeerConnectionStatus.Busy)
      case .offline:
          print("Replicator in offline state")
      case .stopped:
          print("Completed syncing documents")
          handler(PeerConnectionStatus.Error)

      }

      if s.progress.completed == s.progress.total {
          print("All documents synced")
      }
      else {
          print("Documents \(s.progress.total - s.progress.completed) still pending sync")
      }
  })
  return pushPullReplListenerForUserDb
// end::replicator-register-for-events[]




//
// Stuff I adapted
//


import Foundation
import CouchbaseLiteSwift
import MultipeerConnectivity

class cMyPassListener {
  // tag::listener-initialize[]
  fileprivate  var _allowlistedUsers:[[String:String]] = []
  fileprivate var _websocketListener:URLEndpointListener?
  fileprivate var _userDb:Database?
    // Include websockets listener initializer code

    // func fMyPassListener() {
    // tag::listener-config-endpoint[]
    let db=_userDb!
    let listenerConfig = URLEndpointListenerConfiguration(database: db) // <.>
    // tag::listener-config-port[]
    /* optionally */ let wsPort: UInt16 = 4984
    /* optionally */ let wssPort: UInt16 = 4985
    listenerConfig.port =  wssPort
    // end::listener-config-port[]

    // tag::listener-config-netw-iface[]
    listenerConfig.networkInterface = "10.1.1.10"
    // end::listener-config-netw-iface[]
    // end::listener-config-endpoint[]

    // tag::listener-config-tls-full[]
    // This combination will set
    // tag::listener-config-tls-enable[]
    // -- TLS on
    //    optionally switch it off .disableTLS  = true
    listenerConfig.disableTLS  = false // <.>
    // end::listener-config-tls-enable[]
    // tag::listener-config-tls-id-full[]
    // tag::listener-config-tls-id-nil[]
    // -- Use anonymous self-cert
    listenerConfig.tlsIdentity = nil
    // end::listener-config-tls-id-nil[]
    // tag::listener-config-tls-id-cert[]
    // -- Use id and certs from keychain
    listenerConfig.tlsIdentity = TLSIdentity(withLabel:"CBL-Swift-Server-Cert")
    // optionally  listenerConfig.tlsIdentity = TLSIdentity(withIdentity:serverSelfCert-id)
    // end::listener-config-tls-id-cert[]
    // end::listener-config-tls-id-full[]

    // tag::listener-config-auth[]
    listenerConfig.authenticator = ListenerPasswordAuthenticator.init { // <.>
        (username, password) -> Bool in
            if (self._allowlistedUsers.contains(
              ["password" : password, "name":username])) {
                return true
            }
        return false
    }
    // end::listener-config-auth[]

    listenerConfig.enableDeltaSync = true // <.>

    // tag::listener-start[]
    _websocketListener = URLEndpointListener(config: listenerConfig) // <.>

    guard let websocketListener = _websocketListener else {
      throw print("WebsocketsListenerNotInitialized")
      // ... take appropriate actions
    }
    try websocketListener.start() // <.> <.>
    // end::listener-start[]
// end::listener-initialize[]

  }
}


// tag::listener-config-tls-disable[]
listenerConfig.disableTLS  = true
// end::listener-config-tls-disable[]

// tag::listener-config-tls-id-nil[]
listenerConfig.tlsIdentity = nil
// end::listener-config-tls-id-nil[]


// tag::listener-config-delta-sync[]
listenerConfig.enableDeltaSync = true
// end::listener-config-delta-sync[]


// tag::listener-status-check[]
let totalConnections = websocketListener.status.connectionCount
let activeConnections = websocketListener.status.activeConnectionCount
// end::listener-status-check[]


// tag::listener-stop[]
        listener.stop()
// end::listener-stop[]

// tag::listener-config-client-auth-root[]
  // cert is a pre-populated object of type:SecCertificate representing a certificate
  let rootCertData = SecCertificateCopyData(cert) as Data
  let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
  // Listener:
  listenerConfig.authenticator = ListenerCertificateAuthenticator.init (rootCerts: [rootCert])
// end::listener-config-client-auth-root[]


// tag::listener-config-client-auth-self-signed[]
listenerConfig.authenticator = ListenerCertificateAuthenticator.init {
  (cert) -> Bool in
    var cert:SecCertificate
    var certCommonName:CFString?
    let status=SecCertificateCopyCommonName(cert, &certCommonName)
    if (self._allowlistedUsers.contains(["name": certCommonName! as String])) {
        return true
    }
    return false
}
// end::listener-config-client-auth-self-signed[]

// tag::p2p-ws-api-urlendpointlistener[]
public class URLEndpointListener {
    // Properties // <1>
    public let config: URLEndpointListenerConfiguration
    public let port UInt16?
    public let tlsIdentity: TLSIdentity?
    public let urls: Array<URL>?
    public let status: ConnectionStatus?
    // Constructors <2>
    public init(config: URLEndpointListenerConfiguration)
    // Methods <3>
    public func start() throws
    public func stop()
}
// end::p2p-ws-api-urlendpointlistener[]


// tag::p2p-ws-api-urlendpointlistener-constructor[]
let config = URLEndpointListenerConfiguration.init(database: self.oDB)
config.port = tls ? wssPort : wsPort
config.disableTLS = !tls
config.authenticator = auth
self.listener = URLEndpointListener.init(config: config) // <1>
// end::p2p-ws-api-urlendpointlistener-constructor[]


// Active Peer Connection Snippets

//
//  my Other Bits.swift
//  doco-sync
//
//  Created by Ian Bridge on 19/06/2020.
//  Copyright © 2020 Couchbase Inc. All rights reserved.
//

import Foundation
import CouchbaseLiteSwift
import MultipeerConnectivity

class myActPeerClass {

  func fMyActPeer() {
    // tag::p2p-act-rep-func[]
    let user = "syncuser"
    let password = "sync9455"
    let cert:SecCertificate?
    let passivePeerEndpoint = "10.1.1.12:8920"
    let passivePeerPort = "8920"
    let passiveDbName = "userdb"
    var actDb:Database?
    var thisReplicator:Replicator?
    var replicatorListener:ListenerToken?


    // tag::p2p-act-rep-initialize[]
    let tgtUrl = URL(string: "wss://10.1.1.12:8092/actDb")!
    let targetEndpoint = URLEndpoint(url: tgtUrl)
    var config = ReplicatorConfiguration(database: actDb!, target: targetEndpoint) // <.>
    // end::p2p-act-rep-initialize[]

    // tag::p2p-act-rep-config[]
    // tag::p2p-act-rep-config-type[]
    config.replicatorType = .pushAndPull
    // end::p2p-act-rep-config-type[]
    // tag::p2p-act-rep-config-cont[]
    config.continuous = true
    // end::p2p-act-rep-config-cont[]
    // tag::p2p-act-rep-config-cert-verify[]
    // serverCertificateVerificationMode=.selfSignedCert effectively disables cert validation
    config.serverCertificateVerificationMode = .selfSignedCert // <.>
    // end::p2p-act-rep-config-cert-verify[]
    // end::p2p-act-rep-config[]

    // tag::p2p-act-rep-auth[]
    //  Set Authentication Mode
    let authenticator = BasicAuthenticator(username: user, password: password) // <.>
    config.authenticator = authenticator
    // end::p2p-act-rep-auth[]

    // tag::p2p-act-rep-start-full[]
    // Apply configuration settings to the replicator
    thisReplicator = Replicator.init( config: config) // <.>

    // Optionally add a change listener
    // tag::p2p-act-rep-add-change-listener[]
    // add change listener and retain token for use in deletion
    let pushPullReplListener:ListenerToken? = thisReplicator?.addChangeListener({ (change) in // <.>
      if change.status.activity == .stopped {
          print("Replication stopped")
      }
      else {
      // tag::p2p-act-rep-status[]
          print("Replicator is currently ", thisReplicator?.status.activity)
      }
    })
    // end::p2p-act-rep-status[]
// end::p2p-act-rep-add-change-listener[]

// tag::p2p-act-rep-start[]
    // Run the replicator using the config settings
    thisReplicator?.start()  // <.>
// end::p2p-act-rep-start[]
// end::p2p-act-rep-start-full[]


// end::p2p-act-rep-func[]
    }

    func mystopfunc() {
// tag::p2p-act-rep-stop[]
    // Remove the change listener

    thisReplicator?.removeChangeListener(withToken: pushPullReplListener)
    // Stop the replicator
    thisReplicator?.stop()

// end::p2p-act-rep-stop[]
}







// tag::p2p-tlsid-manage-func[]
//
//  cMyGetCert.swift
//  doco-sync
//
//  Created by Ian Bridge on 20/06/2020.
//  Copyright © 2020 Couchbase Inc. All rights reserved.
//

import Foundation
import Foundation
import CouchbaseLiteSwift
import MultipeerConnectivity


class cMyGetCert1{

    let kListenerCertLabel = "doco-sync-server"
    let kListenerCertKeyP12File = "listener-cert-pkey"
    let kListenerPinnedCertFile = "listener-pinned-cert"
    let kListenerCertKeyExportPassword = "couchbase"
    //var importedItems : NSArray
    let thisData : CFData?
    var items : CFArray?

    func fMyGetCert() ->TLSIdentity? {
        var kcStatus = errSecSuccess // Zero
        let thisLabel : String? = "doco-sync-server"

        //var thisData : CFData?
        // tag::p2p-tlsid-check-keychain[]
        // tag::p2p-tlsid-tlsidentity-with-label[]
        // USE KEYCHAIN IDENTITY IF EXISTS
        // Check if Id exists in keychain. If so use that Id
        do {
            if let thisIdentity = try TLSIdentity.identity(withLabel: "doco-sync-server") {
                print("An identity with label : doco-sync-server already exists in keychain")
                return thisIdentity
                }
        } catch
          {return nil}
// end::p2p-tlsid-check-keychain[]
        thisAuthenticator.ClientCertificateAuthenticator(identity: thisIdentity )
        config.thisAuthenticator
// end::p2p-tlsid-tlsidentity-with-label[]


// tag::p2p-tlsid-check-bundled[]
// CREATE IDENTITY FROM BUNDLED RESOURCE IF FOUND

        // Check for a resource bundle with required label to generate identity from
        // return nil identify if not found
        guard let pathToCert = Bundle.main.path(forResource: "doco-sync-server", ofType: "p12"),
                let thisData = NSData(contentsOfFile: pathToCert)
            else
                {return nil}
// end::p2p-tlsid-check-bundled[]

// tag::p2p-tlsid-import-from-bundled[]
        // Use SecPKCS12Import to import the contents (identities and certificates)
        // of the required resource bundle (PKCS #12 formatted blob).
        //
        // Set passphrase using kSecImportExportPassphrase.
        // This passphrase should correspond to what was specified when .p12 file was created
        kcStatus = SecPKCS12Import(thisData as CFData, [String(kSecImportExportPassphrase): "couchbase"] as CFDictionary, &items)
            if kcStatus != errSecSuccess {
             print("failed to import data from provided with error :\(kcStatus) ")
             return nil
            }
        let importedItems = items! as NSArray
        let thisItem = importedItems[0] as! [String: Any]

        // Get SecIdentityRef representing the item's id
        let thisSecId = thisItem[String(kSecImportItemIdentity)]  as! SecIdentity

        // Get Id's Private Key, return nil id if fails
        var thisPrivateKey : SecKey?
        kcStatus = SecIdentityCopyPrivateKey(thisSecId, &thisPrivateKey)
            if kcStatus != errSecSuccess {
                print("failed to import private key from provided with error :\(kcStatus) ")
                return nil
            }

        // Get all relevant certs [SecCertificate] from the ID's cert chain using kSecImportItemCertChain
        let thisCertChain = thisItem[String(kSecImportItemCertChain)] as? [SecCertificate]

        // Return nil Id if errors in key or cert chain at this stage
        guard let pKey = thisPrivateKey, let pubCerts = thisCertChain else {
            return nil
        }
// end::p2p-tlsid-import-from-bundled[]

// tag::p2p-tlsid-store-in-keychain[]
// STORE THE IDENTITY AND ITS CERT CHAIN IN THE KEYCHAIN

        // Store Private Key in Keychain
        let params: [String : Any] = [
            String(kSecClass):          kSecClassKey,
            String(kSecAttrKeyType):    kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass):   kSecAttrKeyClassPrivate,
            String(kSecValueRef):       pKey
        ]
        kcStatus = SecItemAdd(params as CFDictionary, nil)
            if kcStatus != errSecSuccess {
                print("Unable to store private key")
                return nil
            }
       // Store all Certs for Id in Keychain:
       var i = 0;
       for cert in thisCertChain! {
            let params: [String : Any] = [
                String(kSecClass):      kSecClassCertificate,
                String(kSecValueRef):   cert,
                String(kSecAttrLabel):  "doco-sync-server"
                ]
            kcStatus = SecItemAdd(params as CFDictionary, nil)
                if kcStatus != errSecSuccess {
                    print("Unable to store certs")
                    return nil
                }
            i=i+1
        }
// end::p2p-tlsid-store-in-keychain[]

// tag::p2p-tlsid-return-id-from-keychain[]
// RETURN A TLSIDENTITY FROM THE KEYCHAIN FOR USE IN CONFIGURING TLS COMMUNICATION
do {
    return try TLSIdentity.identity(withIdentity: thisSecId, certs: [pubCerts[0]])
} catch {
    print("Error while loading self signed cert : \(error)")
    return nil
}
// end::p2p-tlsid-return-id-from-keychain[]
    } // fMyGetCert
} // cMyGetCert

// end::p2p-tlsid-manage-func[]







// tag::p2p-act-rep-config-self-cert[]
// Use serverCertificateVerificationMode set to `.selfSignedCert` to disable cert validation
config.disableTLS = false
config.serverCertificateVerificationMode = .selfSignedCert
// end::p2p-act-rep-config-self-cert[]


// tag::p2p-act-rep-config-cacert-pinned-func[]
func fMyCaCertPinned() {
  // do {
  let tgtUrl = URL(string: "wss://10.1.1.12:8092/actDb")!
  let targetEndpoint = URLEndpoint(url: tgtUrl)
  let actDb:Database?
  let config = ReplicatorConfiguration(database: actDb!, target: targetEndpoint)
  // tag::p2p-act-rep-config-cacert-pinned[]

  // Get bundled resource and read into localcert
  guard let pathToCert = Bundle.main.path(forResource: "listener-pinned-cert", ofType: "cer")
    else { /* process error */ }
  guard let localCertificate:NSData = NSData(contentsOfFile: pathToCert!)
    else { /* process error */ }

  // Create certificate
  // using its DER representation as a CFData
  guard let pinnedCert = SecCertificateCreateWithData(nil, localCertificate)
    else { /* process error */ }

  // Add `pinnedCert` and `.cacert` to `ReplicatorConfiguration`
  config.serverCertificateVerificationMode = .caCert
  config.pinnedServerCertificate = pinnedCert
  // end::p2p-act-rep-config-cacert-pinned[]
  // end::p2p-act-rep-config-cacert-pinned-func[]
}
