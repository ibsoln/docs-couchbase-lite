// PASSIVE PEER STUFF
// Stuff I adapted
//


import Foundation
import CouchbaseLiteSwift
import MultipeerConnectivity

class cMyPassListener {
    // tag::listener-initialize[]
    // tag::listener-local-db[]
    // . . . preceding application logic . . .
    CouchbaseLite.init(context); <.>
    Database thisDB = new Database("passivepeerdb");

    // end::listener-local-db[]
    // tag::listener-config-db[]
    // Initialize the listener config
    final URLEndpointListenerConfiguration listenerConfig
       = new URLEndpointListenerConfiguration(thisDB); // <.>
    // end::listener-config-db[]
    // tag::listener-config-port[]
    listenerConfig.setPort(55990); //<.>
    // end::listener-config-port[]
    // tag::listener-config-netw-iface[]
    listenerConfig.setNetworkInterface("10.1.1.10"); // <.>
    // end::listener-config-netw-iface[]
    // end::listener-config-db[]
    // tag::listener-deltasync[]
    listenerConfig.setEnableDeltaSync(true); // <.>
    // end::listener-deltasync[]
    // tag::listener-config-tls-full[]
    // tag::listener-config-tls-enable[]
    listenerConfig.setDisableTLS(false); // <.>
    // end::listener-config-tls-enable[]
    // tag::listener-config-tls-id-full[]
    // tag::listener-config-tls-id-SelfSigned[]

    // Use a self-signed certificate
    //    Create a TLSIdentity for the server using convenience API.
    //    System generates self-signed cert

    private static final Map<String, String> CERT_ATTRIBUTES; //<.>
    static {
        final Map<String, String> thisMap = new HashMap<>();
        m.put(TLSIdentity.CERT_ATTRIBUTE_COMMON_NAME, "Couchbase Demo");
        m.put(TLSIdentity.CERT_ATTRIBUTE_ORGANIZATION, "Couchbase");
        m.put(TLSIdentity.CERT_ATTRIBUTE_ORGANIZATION_UNIT, "Mobile");
        m.put(TLSIdentity.CERT_ATTRIBUTE_EMAIL_ADDRESS, "noreply@couchbase.com");
        CERT_ATTRIBUTES = Collections.unmodifiableMap(thisMap);
    }

    // Store the TLS identity in secure storage under the label 'couchbase-demo-cert'
    TLSIdentity thisIdentity = new TLSIdentity.createIdentity(true, CERT_ATTRIBUTES, null, "couchbase-demo-cert"); <.>

    // end::listener-config-tls-id-SelfSigned[]
    // tag::listener-config-tls-id-caCert[]

    // Use CA Cert
    //    Import a key pair into secure storage
    //    Create a TLSIdentity from the imported key-pair
    InputStream thisKeyPair = new FileInputStream();

    thisKeyPair.getClass().getResourceAsStream("serverkeypair.p12");

    TLSIdentity thisIdentity = new TLSIdentity.importIdentity(
      EXTERNAL_KEY_STORE_TYPE,  // KeyStore type, eg: "PKCS12"
      thisKeyPair,              // An InputStream from the keystore
      password,                 // The keystore password
      EXTERNAL_KEY_ALIAS,       // The alias, in the external keystore, of the entry to be used.
      null,                     // The key password
    "test-alias"                // The alias for the imported key
    );

    // end::listener-config-tls-id-caCert[]
    // tag::listener-config-tls-id-anon[]

    // Use an Anonymous Self-Signed Cert
    listenerConfig.setTlsIdentity(null);

    // end::listener-config-tls-id-anon[]
    // tag::listener-config-tls-id-set[]

    // set the TLS Identity
    listenerConfig.setTlsIdentity(thisIdentity); // <.>

    // end::listener-config-tls-id-set[]
    // end::listener-config-tls-id-full[]
    // tag::listener-config-auth-pwd[]

    // Configure the client authenticator (if using Basic Authentication) <.>
    config.setAuthenticator(new ListenerPasswordAuthenticator(
      (thisUser, thisPassword) ->
        username.equals(thisUser) && Arrays.equals(password, thisPassword)));

    // end::listener-config-auth-pwd[]
    // tag::listener-config-auth-cert[]

    // Configure the client authenticator to validate using ROOT CA <.>

    config.setAuthenticator(new ListenerCertificateAuthenticator(certs));

    // end::listener-config-auth-cert[]
    // tag::listener-start[]
    // Initialize the listener
    final URLEndpointListener thisListener
      = new URLEndpointListener(listenerConfig); // <.>

    // start the listener
    thisListener.start(); // <.>
    // end::listener-start[]
    // end::listener-initialize[]
  }

  // tag::listener-config-tls-disable[]
  listenerConfig.disableTLS(true);
  // end::listener-config-tls-disable[]

  // tag::listener-config-tls-id-nil-2[]

  // Use “anonymous” cert. These are self signed certs created by the system
  listenerConfig.setTlsIdentity(nil);
  // end::listener-config-tls-id-nil-2[]


  // tag::listener-config-delta-sync[]
  listenerConfig.enableDeltaSync(true;)
  // end::listener-config-delta-sync[]


  // tag::listener-status-check[]

  int connectionCount = thisListener.getStatus().getConnectionCount(); // <.>

  int activeConnectionCount = thisListener.getStatus().getActiveConnectionCount();  // <.>
  // end::listener-status-check[]


  // tag::listener-stop[]
  thisListener.stop();
  // end::listener-stop[]


// Listener Callouts

// tag::listener-callouts-full[]

  // tag::listener-start-callouts[]
  <.> Initialize the listener instance using the configuration settings.
  <.> Start the listener, ready to accept connections and incoming data from active peers.
  // end::listener-start-callouts[]


  // tag::listener-status-check-callouts[]

  <.> `connectionCount` -- the total number of connections served by the listener
  <.> `activeConnectionCount` -- the number of active (BUSY) connections currently being served by the listener
  //
  // end::listener-status-check-callouts[]

// end::listener-callouts-full[]







// tag::listener-config-client-auth-root[]
  // cert is a pre-populated object of type:SecCertificate representing a certificate
  let rootCertData = SecCertificateCopyData(cert) as Data
  let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
  // Listener:
  listenerConfig.authenticator = ListenerCertificateAuthenticator.init (rootCerts: [rootCert])

  SecCertificate thisCert = new SecCertificate(); // populated as nec.

  Data rootCertData = new Data(SecCertificateCopyData(thisCert));

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


// ACTIVE PEER STUFF
// Replication code
//
// Copyright (c) 2019 Couchbase, Inc All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package com.couchbase.code_snippets;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.couchbase.lite.ArrayFunction;
import com.couchbase.lite.BasicAuthenticator;
import com.couchbase.lite.Blob;
import com.couchbase.lite.Conflict;
import com.couchbase.lite.ConflictResolver;
import com.couchbase.lite.CouchbaseLite;
import com.couchbase.lite.CouchbaseLiteException;
import com.couchbase.lite.DataSource;
import com.couchbase.lite.Database;
import com.couchbase.lite.DatabaseConfiguration;
import com.couchbase.lite.DatabaseEndpoint;
import com.couchbase.lite.Dictionary;
import com.couchbase.lite.Document;
import com.couchbase.lite.DocumentFlag;
import com.couchbase.lite.EncryptionKey;
import com.couchbase.lite.Endpoint;
import com.couchbase.lite.Expression;
import com.couchbase.lite.FullTextExpression;
import com.couchbase.lite.FullTextIndexItem;
import com.couchbase.lite.Function;
import com.couchbase.lite.IndexBuilder;
import com.couchbase.lite.Join;
import com.couchbase.lite.ListenerToken;
import com.couchbase.lite.LogDomain;
import com.couchbase.lite.LogFileConfiguration;
import com.couchbase.lite.LogLevel;
import com.couchbase.lite.Logger;
import com.couchbase.lite.Message;
import com.couchbase.lite.MessageEndpoint;
import com.couchbase.lite.MessageEndpointConnection;
import com.couchbase.lite.MessageEndpointDelegate;
import com.couchbase.lite.MessageEndpointListener;
import com.couchbase.lite.MessageEndpointListenerConfiguration;
import com.couchbase.lite.MessagingCloseCompletion;
import com.couchbase.lite.MessagingCompletion;
import com.couchbase.lite.Meta;
import com.couchbase.lite.MutableDictionary;
import com.couchbase.lite.MutableDocument;
import com.couchbase.lite.Ordering;
import com.couchbase.lite.PredictionFunction;
import com.couchbase.lite.PredictiveIndex;
import com.couchbase.lite.PredictiveModel;
import com.couchbase.lite.ProtocolType;
import com.couchbase.lite.Query;
import com.couchbase.lite.QueryBuilder;
import com.couchbase.lite.ReplicatedDocument;
import com.couchbase.lite.Replicator;
import com.couchbase.lite.ReplicatorConfiguration;
import com.couchbase.lite.ReplicatorConnection;
import com.couchbase.lite.Result;
import com.couchbase.lite.ResultSet;
import com.couchbase.lite.SelectResult;
import com.couchbase.lite.SessionAuthenticator;
import com.couchbase.lite.URLEndpoint;
import com.couchbase.lite.ValueIndex;
import com.couchbase.lite.ValueIndexItem;
import com.couchbase.lite.Where;

public class Examples {
  private static final String TAG = "EXAMPLE ACTIVE PEER";
  private static final String thisDBNAME = "local-database";
  private final Context context;
  // private Database database;
  // private Replicator replicator;

  public Examples(Context context) { this.context = context; }

  String user = "syncuser";
  String password = "sync9455";
  SecCertificate cert=null;
  String passivePeerEndpoint = "10.1.1.12:8920";
  String passivePeerPort = "8920";
  String passiveDbName = "userdb";
  Database thisDB;
  Replicator thisReplicator;
  ListenerToken replicatorListener;

  //@Test
  public void testActPeerSync() throws CouchbaseLiteException, URISyntaxException {
// tag::p2p-act-rep-func[]
    // tag::getting-started[]
    // tag::p2p-act-rep-initialize[]
    // initialize the replicator configuration
    final ReplicatorConfiguration replConfig
       = new ReplicatorConfiguration(thisDB, URLEndpoint(URI("wss://listener.com:port"))); // <.>

    // end::p2p-act-rep-initialize[]
    // tag::p2p-act-rep-config-type[]

    // Set replicator type
    replConfig.setReplicatorType(ReplicatorConfiguration.ReplicatorType.PUSH_AND_PULL);

    // end::p2p-act-rep-config-type[]
    // tag::p2p-act-rep-config-cont[]

    // Configure Sync Mode
    replConfig.setContinuous(true); // default value

    // end::p2p-act-rep-config-cont[]
    // tag::p2p-act-rep-config-tls-full[]
    // tag::p2p-act-rep-config-cacert[]

    // Configure Server Security -- only accept CA Certs
    replConfig.setAcceptOnlySelfSignedServerCertificate(false); <.>

    // end::p2p-act-rep-config-cacert[]
    // tag::p2p-act-rep-config-self-cert[]

    // Configure Server Security -- only accept self-signed certs
    replConfig.setAcceptOnlySelfSignedServerCertificate(true); <.>

    // end::p2p-act-rep-config-self-cert[]
    // tag::p2p-act-rep-config-pinnedcert[]

    // Return the remote pinned cert (the listener's cert)
    byte returnedCert = new byte(replConfig.getPinnedCertificate()); // Get listener cert if pinned
    // end::p2p-act-rep-config-pinnedcert[]
    // Configure Client Security // <.>
    // tag::p2p-act-rep-auth[]
    // Configure basic auth using user credentials
    final BasicAuthenticator thisAuth = new BasicAuthenticator("thisUsername", "thisPasswordValue"));

    replConfig.setAuthenticator(thisAuth)

    // end::p2p-act-rep-auth[]
    // end::p2p-act-rep-config-tls-full[]
    // tag::p2p-tlsid-tlsidentity-with-label[]

    Work in progress. Code snippet to be provided.

    // end::p2p-tlsid-tlsidentity-with-label[]
    // tag::p2p-act-rep-config-cacert-pinned[]

    // Only CA Certs accepted
    config.setAcceptOnlySelfSignedServerCertificate(false); // <.>

    // Configure the pinned certificate from the byte array (cert)
    config.setPinnedServerCertificate(cert.getEncoded()); // <.>

    // end::p2p-act-rep-config-cacert-pinned[]

    /* Optionally set custom conflict resolver call back */
    replConfig.setConflictResolver( /* define resolver function */); // <.>
    // tag::p2p-act-rep-start-full[]

    // Create replicator (be sure to hold a reference somewhere that will prevent the Replicator from being GCed)
    final Replicator thisReplicator = new Replicator(replConfig); // <.>

    // tag::p2p-act-rep-add-change-listener[]

    // Optionally add a change listener
    ListenerToken thisListener = new thisReplicator.addChangeListener(change -> { // <.>
      if (change.getStatus().getError() != null) {
        Log.i(TAG, "Error code ::  " + change.getStatus().getError().getCode());
      }
    });

    // end::p2p-act-rep-add-change-listener[]
    // tag::p2p-act-rep-start[]

      // Initialize replicator with configuration data
    final Replicator thisReplicator = new Replicator(config);

    // Start replicator
    thisReplicator.start(false); // <.>

    // end::p2p-act-rep-start[]
  }
// end::p2p-act-rep-start-full[]
// end::p2p-act-rep-func[]         ***** End p2p-act-rep-func
}
    // tag::p2p-act-rep-status[]

    Log.i(TAG, "The Replicator is currently " + thisReplicator.getStatus().getActivityLevel());

    Log.i(TAG, "The Replicator has processed " + t);

    if (thisReplicator.getStatus().getActivityLevel() == Replicator.ActivityLevel.BUSY) {
          Log.i(TAG, "Replication Processing");
          Log.i(TAG, "It has completed " + thisReplicator.getStatus().getProgess().getTotal() + " changes");
      }
      // end::p2p-act-rep-status[]

      // tag::p2p-act-rep-stop[]
      // Stop replication.
      thisReplicator.stop(); // <.>
      // end::p2p-act-rep-stop[]


  }

{
  CouchbaseLite.init(context);
  Database thisDB = new Database("passivepeerdb");  // <.>
  // Initialize the listener config
  final URLEndpointListenerConfiguration listenerConfig = new URLEndpointListenerConfiguration(database);
  listenerConfig.setPort(55990)             // <.> Default- port is selected
  listenerConfig.setDisableTls(false)       // <.> Optional. Defaults to false. You get TLS encryption out-of-box
  listenerConfig.setEnableDeltaSync(true)   // <.> Optional. Defaults to false.

  // Configure the client authenticator (if using basic auth)
  ListenerPasswordAuthenticator auth = new ListenerPasswordAuthenticator { "username", "password"}; // <.>
  listenerConfig.setAuthenticator(auth); // <.>

  // Initialize the listener
  final URLEndpointListener listener = new URLEndpointListener( listenerConfig ); // <.>

  // Start the listener
  listener.start(); // <.>
    }


// tag::createTlsIdentity[]

Map<String, String> X509_ATTRIBUTES = mapOf(
           TLSIdentity.CERT_ATTRIBUTE_COMMON_NAME to "Couchbase Demo",
           TLSIdentity.CERT_ATTRIBUTE_ORGANIZATION to "Couchbase",
           TLSIdentity.CERT_ATTRIBUTE_ORGANIZATION_UNIT to "Mobile",
           TLSIdentity.CERT_ATTRIBUTE_EMAIL_ADDRESS to "noreply@couchbase.com"
       )

TLSIdentity thisIdentity = new TLSIdentity.createIdentity(true, X509_ATTRIBUTES, null, "test-alias");

// end::createTlsIdentity[]



// tag::deleteTlsIdentity[]

  String thisAlias = "alias-to-delete";
  final KeyStore thisKeyStore =  KeyStore.getInstance("PKCS12");
  thisKeyStore.load(null);
  thisKeyStore.deleteEntry(thisAlias);


// end::deleteTlsIdentity[]

// tag::retrieveTlsIdentity[]
// OPTIONALLY:: Retrieve a stored TLS identity using its alias/label

TLSIdentity thisIdentity = new TLSIdentity.getIdentity("CBL-Demo-Server-Cert")
// end::retrieveTlsIdentity[]


    // Configure the client authenticator (if using Basic Authentication)
    // String thisUser = new String("validUsername"); // an example username
    // String thisPassword = new String("validPasswordValue"); // an example password

    // ListenerPasswordAuthenticator thisAuth = new ListenerPasswordAuthenticator( // <.>
    //   thisUser, thisPassword -> thisUser == "validUsername" && thisPassword == "validPasswordValue" );

    // if (thisAuth) {
    //   listenerConfig.setAuthenticator(auth);
    // }
    // else {
    //   // . . . authentication failed take appropriate exception action
    //   return
    // };




    // tag::old-p2p-act-rep-add-change-listener[]
    ListenerToken thisListener = new thisReplicator.addChangeListener(change -> { // <.>
      if (change.getStatus().getError() != null) {
        Log.i(TAG, "Error code ::  " + change.getStatus().getError().getCode());
      }
    });

    // end::old-p2p-act-rep-add-change-listener[]



// g u b b i n s
// tag::duff-p2p-tlsid-tlsidentity-with-label[]


    // Configure TLS Cert CA auth using key-stored cert id alias 'doc-sync-server'

    // TLSIdentity thisIdentity = new TLSIdentity.getIdentity("doc-sync-server"); // Get existing TLS ID from sec storage

    // ClientCertificateAuthenticator thisAuth = new ClientCertificateAuthenticator(thisIdentity);

    // replConfig.setAuthenticator(thisAuth);



    // USE KEYCHAIN IDENTITY IF EXISTS
    // Check if Id exists in keychain. If so use that Id

    // STILL NEED TO REFACTOR

    do {
      if let thisIdentity = try TLSIdentity.identity(withLabel: "doco-sync-server") {
          print("An identity with label : doco-sync-server already exists in keychain")
          return thisIdentity
          }
    } catch
    {return nil}
    thisAuthenticator.ClientCertificateAuthenticator(identity: thisIdentity )
    config.thisAuthenticator

    // end::duff-p2p-tlsid-tlsidentity-with-label[]


// tag::old-deleteTlsIdentity[]

String thisAlias = "alias-to-delete";
KeyStore thisKeystore = KeyStore.getInstance("PKCS12"); // <.>
thisKeyStore.load(null);
if (thisAlias != null) {
   thisKeystore.deleteEntry(thisAlias);  // <.>
}

// end::old-deleteTlsIdentity[]


// C A L L O U T S

// tag::p2p-act-rep-config-cacert-pinned-callouts[]
<.> Configure to accept only CA certs
<.> Configure the pinned certificate using data from the byte array `cert`
// end::p2p-act-rep-config-cacert-pinned-callouts[]
