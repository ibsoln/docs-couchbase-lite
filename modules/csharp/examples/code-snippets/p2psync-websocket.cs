// PASSIVE PEER STUFF
// Stuff I adapted
//
//
// p2pSync-websockets.cs
//
// Copyright (c) 2017 Couchbase, Inc All rights reserved.
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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Couchbase.Lite;
using Couchbase.Lite.Enterprise.Query;
using Couchbase.Lite.Logging;
using Couchbase.Lite.P2P;
using Couchbase.Lite.Query;
using Couchbase.Lite.Sync;
using Newtonsoft.Json;

using SkiaSharp;
namespace api_walkthrough
{
  class Program
  {
  private static Database _Database;
  private static Replicator _Replicator;
  private static ListenerToken _ThisListenerToken;
  private static bool _NeedsExtraDocs;

  #region Private Methods
  private static void GettingStarted()
  {
    // tag::listener-initialize[]
    // tag::listener-local-db[]
    // . . . preceding application logic . . .
    // Get the database (and create it if it doesn't exist)
    var thisDB = new Database("mydb");

    // end::listener-local-db[]
    // tag::listener-config-db[]
    // Initialize the listener config
    var thisConfig = new URLEndpointListenerConfiguration(thisDB); // <.>

    // end::listener-config-db[]
    // tag::listener-config-port[]
    thisConfig.Port = 55990; //<.>

    // end::listener-config-port[]
    // tag::listener-config-netw-iface[]
    thisConfig.NetworkInterface = "10.1.1.10"; // <.>

    // end::listener-config-netw-iface[]
    // tag::listener-config-delta-sync[]
    thisConfig.EnableDeltaSync = true; // <.>

    // end::listener-config-delta-sync[]
    // tag::listener-config-tls-full[]
    // tag::listener-config-tls-enable[]
    thisConfig.DisableTLS = false; // <.>

    // end::listener-config-tls-enable[]
    // tag::listener-config-tls-disable[]
    thisConfig.DisableTLS = true; // <.>

    // end::listener-config-tls-disable[]
    // tag::listener-config-tls-id-full[]
    // tag::listener-config-tls-id-SelfSigned[]
    // Use a self-signed certificate
    // Create a TLSIdentity for the server using convenience API.
    // System generates self-signed cert
    // Work-in-progress. Code snippet coming soon.
    // Store the TLS identity in secure storage
    // under the label 'couchbase-demo-cert'
    var thisTlsID = new TLSIdentity.createIdentity(
          true,
          new Dictionary<string,string>() {
            {Certificate.CommonNameAttribute, "CBL-Server"};
            },
          null,
          _ourX509store,
          "couchbase-demo-cert"
          );  // <.>

    // end::listener-config-tls-id-SelfSigned[]
    // tag::listener-config-tls-id-caCert[]
    // Use CA Cert
    //    Import a key pair into secure storage
    //    Create a TLSIdentity from the imported key-pair
    byte[] thisKeyPair = File.ReadAllBytes("serverkeypair.p12");
    var thisIdentity = TLSIdentity.ImportIdentity(
                          _store, // x509store
                          thisKeyPair, // byte array of PKCS12 data
                          "123", // store password
                          "couchbase-demo-cert", // alias label
                          null); // <.>

    // end::listener-config-tls-id-caCert[]
    // tag::listener-config-tls-id-anon[]
    // Use an Anonymous Self-Signed Cert
    thisConfig.TlsIdentity = null; // <.>

    // end::listener-config-tls-id-anon[]
    // tag::listener-config-tls-id-set[]
    // Set the TLS Identity
    thisConfig.TlsIdentity = thisIdentity; // <.>

    // end::listener-config-tls-id-set[]
    // end::listener-config-tls-id-full[]
    // tag::listener-config-client-auth-pwd[]
    // Configure the client authenticator (if using Basic Authentication) <.>
    SecureString thisPassword = "valid.password"; /* example only */
    var thisUser = "valid.user";
    thisConfig.Authenticator = new ListenerPasswordAuthenticator(
      (sender, thisUser, thisPassword) =>
        {
          return username.equals("valid.user")  && thisPassword == "valid.password");
        }
      );

    // end::listener-config-client-auth-pwd[]
    // tag::listener-config-client-root-ca[]
    // Configure the client authenticator
    // to validate using ROOT CA <.>
    byte[] thisCaData; // byte array for CA data
    using (var thisReader = new BinaryReader(stream)) {
      thisCaData = thisReader.ReadBytes(int stream.Length);
    }; // Get cert data

    var thisRootCert = new X509Certificate(thisCaData); //

    thisConfig.Authenticator = new ListenerCertificateAuthenticator(
      new X509Certificate2XXollection(thisRootCert)
    );

    // end::listener-config-client-root-ca[]
    // tag::listener-config-client-auth-self-signed[]
    // Work in progress. Code snippet to be provided.
    // end::listener-config-client-auth-self-signed[]
    // tag::listener-start[]
    // Initialize the listener
    var thisListener = new URLEndpointListener(thisConfig); // <.>

    // Start the listener
    thisListener.start(); // <.>

    // end::listener-start[]
    // end::listener-initialize[]
  }

  // tag::old-listener-config-tls-disable[]
  thisConfig.disableTLS = true;
  // end::old-listener-config-tls-disable[]

  // tag::listener-config-tls-id-nil-2[]

  // Use “anonymous” cert. These are self signed certs created by the system
  thisConfig.TlsIdentity = null;
  // end::listener-config-tls-id-nil-2[]


  // tag::old-listener-config-delta-sync[]
  thisConfig.EnableDeltaSync = true;
  // end::old-listener-config-delta-sync[]


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
  // Work in progress. Code snippet to be provided.

  // end::listener-config-client-auth-root[]


  // prev content of listener-config-client-auth-self-signed (for ios)
  thisConfig.authenticator = ListenerCertificateAuthenticator.init {
    (cert) -> Bool in
    var cert:SecCertificate
    var certCommonName:CFString?
    let status=SecCertificateCopyCommonName(cert, &certCommonName)
    if (self._allowlistedUsers.contains(["name": certCommonName! as String])) {
      return true
    }
    return false
  }
  // tag::listener-config-client-auth-self-signed[]
  // Work in progress. Code snippet to be provided.

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
thisConfig.port = tls ? wssPort : wsPort
thisConfig.disableTLS = !tls
thisConfig.authenticator = auth
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
    // . . . preceding code. for example . . .
    private static ListenerToken _thisListenerToken;
    var Database thisDB;
    // . . . other code . . .
    // tag::p2p-act-rep-initialize[]
    // initialize the replicator configuration

    var thisListener = new URLEndpoint("wss://listener.com:4984/otherDB"); // <.>
    var config = new ReplicatorConfiguration(thisDB, thisListener);

    // end::p2p-act-rep-initialize[]
    // tag::p2p-act-rep-config-type[]

    // Set replicator type
    thisConfig.ReplicatorType = ReplicatorType.PushAndPull;

    // end::p2p-act-rep-config-type[]
    // tag::p2p-act-rep-config-cont[]
    // Configure Sync Mode
    thisConfig.Continuous = true; // default value

    // end::p2p-act-rep-config-cont[]
    // tag::p2p-act-rep-config-tls-full[]
    // tag::p2p-act-rep-config-cacert[]
    // Configure Server Security -- only accept CA Certs
    thisConfig.AcceptOnlySelfSignedServerCertificate = false; // <.>

    // end::p2p-act-rep-config-cacert[]
    // tag::p2p-act-rep-config-self-cert[]
    // Configure Server Security -- only accept self-signed certs
    thisConfig.AcceptOnlySelfSignedServerCertificate = true; // <.>

    // end::p2p-act-rep-config-self-cert[]
    // tag::p2p-act-rep-config-pinnedcert[]

    // Return the remote pinned cert (the listener's cert)
    byte returnedCert = new byte(thisConfig.getPinnedCertificate()); // Get listener cert if pinned
    // end::p2p-act-rep-config-pinnedcert[]
    // Configure Client Security // <.>
    // tag::p2p-act-rep-auth[]
    // Configure basic auth using user credentials
    thisConfig.Authenticator = new BasicAuthenticator(thisUser, thisPassword);

    // end::p2p-act-rep-auth[]
    // end::p2p-act-rep-config-tls-full[]
    // tag::p2p-tlsid-tlsidentity-with-label[]

    Work in progress. Code snippet to be provided.

    // end::p2p-tlsid-tlsidentity-with-label[]
    // tag::p2p-act-rep-config-cacert-pinned[]
    // Only CA Certs accepted
    thisConfig.AcceptOnlySelfSignedServerCertificate = false; // <.>
    // Use the pinned certificate from the byte array (caData)
    var thisCert = new X509Certificate2(caData);
    thisConfig.PinnedServerCertificate = thisCert; // <.>

    // end::p2p-act-rep-config-cacert-pinned[]
    // tag::p2p-act-rep-config-conflict-full[]
    // tag::p2p-act-rep-config-conflict-builtin[]
    /* Optionally set a conflict resolver call back */ // <.>
    // Use built-in resolver
    thisConfig.ConflictResolver = new LocalWinConflictResolver();  //

    // end::p2p-act-rep-config-conflict-builtin[]
    // tag::p2p-act-rep-config-conflict-custom[]
    // optionally use custom resolver
    thisConfig.ConflictResolver = new ConflictResolver(
      (conflict) => {
        /* define resolver function */
      }
    ); //

    // end::p2p-act-rep-config-conflict-custom[]
    // end::p2p-act-rep-config-conflict-full[]
    // tag::p2p-act-rep-start-full[]
    // Initialize and start a replicator
    // Initialize replicator with configuration data
    var thisReplicator = new Replicator(thisConfig); // <.>

    // tag::p2p-act-rep-add-change-listener[]
    // Optionally add a change listener
    _ThisListenerToken = thisReplicator.AddChangeListener((sender, args) =>
      {
        if (args.Status.Activity == ReplicatorActivityLevel.Stopped) {
            Console.WriteLine("Replication stopped");
        }
      }); // <.>

    // end::p2p-act-rep-add-change-listener[]
    // tag::p2p-act-rep-start[]
    // Start replicator
    thisReplicator.Start(); // <.>

    // end::p2p-act-rep-start[]
// end::p2p-act-rep-start-full[]
// end::p2p-act-rep-func[]         ***** End p2p-act-rep-func
}
    // Code to refactor
    Log.i(TAG, "The Replicator is currently " + thisReplicator.getStatus().getActivityLevel());

    Log.i(TAG, "The Replicator has processed " + t);

    if (thisReplicator.getStatus().getActivityLevel() == Replicator.ActivityLevel.BUSY) {
          Log.i(TAG, "Replication Processing");
          Log.i(TAG, "It has completed " + thisReplicator.getStatus().getProgess().getTotal() + " changes");
      }
    // tag::p2p-act-rep-status[]
    //WIP -  NEEDS REFACTORING AS C#
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
  final URLEndpointListenerConfiguration thisConfig = new URLEndpointListenerConfiguration(database);
  thisConfig.Port(55990)             // <.> Default- port is selected
  thisConfig.DisableTls(false)       // <.> Optional. Defaults to false. You get TLS encryption out-of-box
  thisConfig.EnableDeltaSync(true)   // <.> Optional. Defaults to false.

  // Configure the client authenticator (if using basic auth)
  ListenerPasswordAuthenticator auth = new ListenerPasswordAuthenticator { "username", "password"}; // <.>
  thisConfig.Authenticator(auth); // <.>

  // Initialize the listener
  final URLEndpointListener listener = new URLEndpointListener( thisConfig ); // <.>

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
// tag::p2p-tlsid-delete-id-from-keychain[]
TLSIdentity.DeleteIdentity(_store, "alias-to-delete", null);

// end::p2p-tlsid-delete-id-from-keychain[]
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
    //   thisConfig.Authenticator(auth);
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

    // thisConfig.Authenticator(thisAuth);



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
    thisConfig.thisAuthenticator

    // end::duff-p2p-tlsid-tlsidentity-with-label[]


// tag::old-deleteTlsIdentity[]

String thisAlias = "alias-to-delete";
KeyStore thisKeystore = KeyStore.getInstance("PKCS12"); // <.>
thisKeyStore.load= null;
if (thisAlias != null) {
   thisKeystore.deleteEntry(thisAlias);  // <.>
}

// end::old-deleteTlsIdentity[]


// cert auth
let rootCertData = SecCertificateCopyData(cert) as Data
let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
// Listener:
thisConfig.authenticator = ListenerCertificateAuthenticator.init (rootCerts: [rootCert])

SecCertificate thisCert = new SecCertificate(); // populated as nec.

Data rootCertData = new Data(SecCertificateCopyData(thisCert));

let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
// Listener:
thisConfig.authenticator = ListenerCertificateAuthenticator.init (rootCerts: [rootCert])
// cert auth


// C A L L O U T S

// tag::p2p-act-rep-config-cacert-pinned-callouts[]
<.> Configure to accept only CA certs
<.> Configure the pinned certificate using data from the byte array `cert`
// end::p2p-act-rep-config-cacert-pinned-callouts[]
