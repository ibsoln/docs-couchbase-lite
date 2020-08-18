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
  fileprivate var thisDB:Database?
    // Include websockets listener initializer code

    // func fMyPassListener() {
    // tag::listener-config-db[]
    CBLDatabase *db = self.db;

    CBLURLEndpointListenerConfiguration* listenerConfig; // <.>
    listenerConfig = [[CBLURLEndpointListenerConfiguration alloc] initWithDatabase: database];

    // tag::listener-config-port[]
    /* optionally */ int *wsPort = 4984;
    /* optionally */ int *wssPort = 4985;
    listenerConfig.port =  wssPort;
    // end::listener-config-port[]

    // tag::listener-config-netw-iface[]
    NSURL *thisURL = [NSURL URLWithString:@"10.1.1.10"];
    listenerConfig.networkInterface = thisURL;
    // end::listener-config-netw-iface[]
    // end::listener-config-db[]

    // tag::listener-config-tls-full[]
    // This combination will set
    // tag::listener-config-tls-enable[]
    // -- TLS on
    //    optionally switch it off .disableTLS  = true
    listenerConfig.disableTLS  = false; // <.>
    // end::listener-config-tls-enable[]
    // tag::listener-config-tls-id-full[]
    // tag::listener-config-tls-id-nil[]
    // -- Use anonymous self-cert
    listenerConfig.tlsIdentity = nil; // Use with anonymous self signed cert
    // end::listener-config-tls-id-nil[]
    // tag::listener-config-tls-id-cert[]
    // -- Use id and certs from keychain
    listenerConfig.tlsIdentity = TLSIdentity(withLabel:"CBL-Swift-Server-Cert")
    // optionally  listenerConfig.tlsIdentity = TLSIdentity(withIdentity:serverSelfCert-id)
    // end::listener-config-tls-id-cert[]
    // end::listener-config-tls-id-full[]

    - (BOOL) isValidCredentials: (NSString*)u password: (NSString*)p { return YES; } // helper

    listenerConfig.authenticator = [[CBLListenerPasswordAuthenticator alloc] initWithBlock: ^BOOL(NSString * username, NSString * password) {
        if ([self isValidCredentials: username password:password]) {
            return  YES;
        }
        return NO;
    }];

    // end::listener-config-auth[]

    listenerConfig.enableDeltaSync = true // <.>

    // tag::listener-start[]

    CBLURLEndpointListener* websocketListener = nil;
    websocketListener = [[CBLURLEndpointListener alloc] initWithConfig: listenerConfig]; // <.>
    }

    BOOL success = [websocketListener startWithError: &error];
    if (!success) {
        NSLog(@"Cannot start the listener: %@", error);
    } // <.> <.>
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
