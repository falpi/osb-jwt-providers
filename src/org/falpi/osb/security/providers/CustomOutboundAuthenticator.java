// ##################################################################################################################################
// VERSIONING
// ##################################################################################################################################
// $Revision: 1951 $
// $Date: 2026-03-13 17:41:24 +0100 (Fri, 13 Mar 2026) $
// ##################################################################################################################################

package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.Map;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;

import javax.security.auth.login.AppConfigurationEntry;

import weblogic.management.security.ProviderMBean;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.wsee.wsdl.WsdlBinding;
import weblogic.wsee.wsdl.WsdlBindingOperation;
import weblogic.wsee.wsdl.soap11.SoapBinding;
import weblogic.wsee.wsdl.soap11.SoapBindingOperation;
import weblogic.wsee.wsdl.soap12.Soap12Binding;
import weblogic.wsee.wsdl.soap12.Soap12BindingOperation;

import com.bea.wli.config.Ref;
import com.bea.wli.config.component.NotFoundException;
import com.bea.wli.sb.context.MessageContext;
import com.bea.wli.sb.context.OutboundEndpoint;
import com.bea.wli.sb.pipeline.PipelineContext;
import com.bea.wli.sb.pipeline.RouterCallback;
import com.bea.wli.sb.pipeline.RouterContext;
import com.bea.wli.sb.resources.service.CommonServiceRepository;
import com.bea.wli.sb.resources.wsdl.EffectiveWSDL;
import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.RequestHeaders;
import com.bea.wli.sb.transports.RequestMetaData;
import com.bea.wli.sb.transports.TransportEndPoint;
import com.bea.wli.sb.transports.TransportException;
import com.bea.wli.sb.transports.TransportSender;
import com.bea.wli.sb.transports.http.OutboundAuthentication;
import com.bea.wli.sb.transports.http.HttpUrlConnectionFactory;
import com.bea.wli.sb.services.dispatcher.security.SecurityContext;


import org.apache.xmlbeans.XmlObject;

import org.json.JSONObject;

import org.falpi.utils.*;
import org.falpi.SuperMap;
import org.falpi.osb.security.providers.CustomAuthenticator.RuntimeConfig;
import org.falpi.osb.security.providers.CustomAuthenticator.RuntimeContext;
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.StringUtils.*;
import org.falpi.utils.jwt.JWTCache.*;
import org.falpi.utils.jwt.JWTProvider;
import org.falpi.utils.jwt.JWTProvider.*;
import org.falpi.utils.logging.*;

// ##################################################################################################################################
// Classe principale
// ##################################################################################################################################

public class CustomOutboundAuthenticator extends CustomAuthenticator implements AuthenticationProviderV2, OutboundAuthentication {
   
   // ##################################################################################################################################
   // Costanti 
   // ##################################################################################################################################
   
   public static final String JWT_POLICIES_PATH          = "JWT_POLICIES_PATH";
   public static final String JWT_TEMPLATES_PATH         = "JWT_TEMPLATES_PATH";
   public static final String JWT_CLIENT_KEYS_PATH       = "JWT_CLIENT_KEYS_PATH";
   public static final String JWT_CLIENT_SECRETS_PATH    = "JWT_CLIENT_SECRETS_PATH";
   public static final String JWT_HEADER_SECRETS_PATH    = "JWT_HEADER_SECRETS_PATH";
   public static final String JWT_RESOURCE_MAPPING_PATH  = "JWT_RESOURCE_MAPPING_PATH";
   public static final String CUSTOM_REQUEST_HEADERS     = "CUSTOM_REQUEST_HEADERS";
   public static final String ENCRYPTION_HELPER          = "ENCRYPTION_HELPER";
   
   // ##################################################################################################################################
   // Variabili
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Variabili globali statiche di classe
   // ==================================================================================================================================

   // Contatore istanze del provider
   protected static byte IntInstanceCount = 0; 
   
   // Registro delle istanze del provider di outbound
   protected static ProviderRegistry ObjOutboundRegistry = new ProviderRegistry();
 
   // ##################################################################################################################################
   // Costruttore
   // ##################################################################################################################################
   public CustomOutboundAuthenticator() {
      super();      
      StrInstanceID = "COA:"+String.format("%03X",IntInstanceCount++);      
   }
   
   // ##################################################################################################################################
   // Implementa interfacce per security provider 
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {       
      
      // Richiama costruttore padre
      init(ObjMBean);
         
      // Prepara logger
      LogManager Logger = getLogger();
      
      // Se esiste gia' un provider di outbound registrato genera eccezione (e' ammessa una sola istanza)
      if (!ObjOutboundRegistry.isEmpty()) {         
         String StrError = "Multiple outbound providers not allowed";
         Logger.logMessage(LogLevel.ERROR,StrError);
         System.exit(0);
      }
            
      // Salva l'istanza del provider di outbound nel registry    
      ObjOutboundRegistry.put(ObjProviderContext.providerName,this);                  
   }

   @Override
   public void shutdown() {
      done();
   }

   @Override
   public String getDescription() {
      return ObjProviderContext.providerTitle;
   }

   @Override
   public IdentityAsserterV2 getIdentityAsserter() {
      return null;
   }

   @Override
   public PrincipalValidator getPrincipalValidator() {
      return null;
   }

   @Override
   public AppConfigurationEntry getLoginModuleConfiguration() {
      return null;
   }

   @Override
   public AppConfigurationEntry getAssertionModuleConfiguration() {
      return null;
   }

   // ##################################################################################################################################
   // Implementa interfacce di outbound security (OutboundAuthentication)
   // ##################################################################################################################################
   
   @Override
   public void doOutboundAuthentication(TransportEndPoint ObjEndpoint,TransportSender ObjSender,Ref ObjServiceAccountRef,
                                        HttpUrlConnectionFactory ObjConnectionFactory) throws TransportException {
      
      // Inizializza nome del thread
      setThreadName();
      
      // Crea logger 
      LogManager Logger = createLogger();

      // Acquisisce request connection
      HttpURLConnection ObjConnection = ObjConnectionFactory.newConnection();

      // Se non è registrato il provider di outbound genera eccezione
      if (ObjOutboundRegistry.isEmpty()) throw new TransportException("Custom Outbound provider not configured in security realm");         
      
      // Se il business service è associato ad un service account genera eccezione
      if (ObjServiceAccountRef!=null) throw new TransportException("Service Account not allowed ("+ObjEndpoint.getServiceRef().getFullName()+")");       
          
      // ==================================================================================================================================
      // Se necessario inizializza contesto dell'istanza per accesso alle policy di sicurezza globali
      // ==================================================================================================================================   

      // Se non c'è ancora nessun provider di outbound agganciato all'istanza dell'autenticator estrae il primo registrato
      if (ObjProviderContext==null) {
         ObjProviderContext = ObjOutboundRegistry.values().iterator().next().ObjProviderContext;
         Logger.logMessage(LogLevel.WARN,"Provider context init ("+ObjProviderContext.providerName+")");
      }
                         
      // ==================================================================================================================================
      // Inizializza context
      // ==================================================================================================================================   
                         
      // Crea config & context
      RuntimeConfig Config = createConfig();
      RuntimeContext Context = createContext(ObjEndpoint,ObjSender,ObjConnection);

      // ==================================================================================================================================      
      // Esegue in modo sincrono o asincrono in base a configurazione
      // ==================================================================================================================================
      if (Config.getString(THREADING_MODE).equals("SERIAL")) {
         doOutboundAuthenticationSynchImpl();
      } else {      
         doOutboundAuthenticationAsynchImpl();
      }
      
      // ==================================================================================================================================      
      // Ripulisce esplicitamente le variabili di thread
      // ==================================================================================================================================      
      cleanThread();
   }

   // ==================================================================================================================================
   // Implementazione sincrona (serializza le richieste consentendo solo un thread alla volta)
   // ==================================================================================================================================   
   private synchronized void doOutboundAuthenticationSynchImpl() throws TransportException {      
      doOutboundAuthenticationAsynchImpl();  
   }
   
   // ==================================================================================================================================
   // Implementazione asincrona (consente esecuzione parallela delle richieste)
   // ==================================================================================================================================
   private void doOutboundAuthenticationAsynchImpl() throws TransportException {
      
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();   
      
      // Imposta padding
      Logger.setPadLength(29);   
      
      // ==================================================================================================================================
      // Gestisce asserzione di debug
      // ==================================================================================================================================   
      manageDebuggingAssertion();
      
      // ==================================================================================================================================
      // Logging configurazione
      // ==================================================================================================================================
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"OUTBOUND AUTH");
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CONFIGURATION");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logProperty(LogLevel.DEBUG,"PROVIDER_TYPE",Config.getString(PROVIDER_TYPE));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_LINES",Config.getString(LOGGING_LINES));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_LEVEL",Config.getString(LOGGING_LEVEL));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_INFO",Config.getString(LOGGING_INFO));
         Logger.logProperty(LogLevel.DEBUG,"THREADING_MODE",Config.getString(THREADING_MODE));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_SSL_VERIFY",Config.getString(REQUESTS_SSL_VERIFY));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_CONN_TIMEOUT",Config.getString(REQUESTS_CONN_TIMEOUT)); 
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_READ_TIMEOUT",Config.getString(REQUESTS_READ_TIMEOUT));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_PROXY_MODE",Config.getString(REQUESTS_PROXY_MODE));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_PROXY_PATH",Config.getString(REQUESTS_PROXY_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_POLICIES_PATH",Config.getString(JWT_POLICIES_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_TEMPLATES_PATH",Config.getString(JWT_TEMPLATES_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_CLIENT_KEYS_PATH",Config.getString(JWT_CLIENT_KEYS_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_CLIENT_SECRETS_PATH",Config.getString(JWT_CLIENT_SECRETS_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_HEADER_SECRETS_PATH",Config.getString(JWT_HEADER_SECRETS_PATH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_RESOURCE_MAPPING_PATH",Config.getString(JWT_RESOURCE_MAPPING_PATH));
         Logger.logProperty(LogLevel.DEBUG,"CUSTOM_REQUEST_HEADERS",StringUtils.join(Config.getProperties(CUSTOM_REQUEST_HEADERS),","));
         Logger.logProperty(LogLevel.DEBUG,"DEBUGGING_ASSERTION",StringUtils.join(Config.getStringArray(DEBUGGING_ASSERTION)," "));
         Logger.logProperty(LogLevel.DEBUG,"DEBUGGING_PROPERTIES",StringUtils.join(Config.getStringArray(DEBUGGING_PROPERTIES),","));                
         Logger.logMessage(LogLevel.TRACE,"------------------------------------------------------------------------------------------");
      } 
      
      // ==================================================================================================================================
      // Controlli di congruenza ed eventuale pulizia della configurazione
      // ==================================================================================================================================
      try {
         validateParameter(LOGGING_LINES);         

         validateParameter(JWT_POLICIES_PATH);
         validateParameter(JWT_TEMPLATES_PATH);
         validateParameter(JWT_CLIENT_KEYS_PATH);
         validateParameter(JWT_CLIENT_SECRETS_PATH);
         validateParameter(JWT_HEADER_SECRETS_PATH);
         validateParameter(JWT_RESOURCE_MAPPING_PATH);
         
         if (!Config.getString(REQUESTS_PROXY_MODE).equals("DIRECT")) validateParameter(REQUESTS_PROXY_PATH);      
         
      } catch (Exception ObjException) {
         throw new TransportException(ObjException.getMessage());
      }
      
      // ==================================================================================================================================
      // Logging contesto
      // ==================================================================================================================================
            
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CONTEXT");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logProperty(LogLevel.DEBUG,"Managed Name",Context.getString("wls.managed"));
         Logger.logProperty(LogLevel.DEBUG,"Project Name",Context.getString("osb.project"));
         Logger.logProperty(LogLevel.DEBUG,"Service Name",Context.getString("osb.service.name"));           
         Logger.logProperty(LogLevel.DEBUG,"Operation Name",Context.getString("osb.operation"));           
         Logger.logProperty(LogLevel.DEBUG,"Operation Source",Context.getString("osb.operation.source"));           
         Logger.logProperty(LogLevel.DEBUG,"Operation Message",Context.getString("osb.operation.message"));           
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      }     
       
      // ==================================================================================================================================
      // Gestisce acquisizione e validazione delle policy
      // ==================================================================================================================================
      preparePolicies();
      
      // ==================================================================================================================================
      // Gestisce l'autenticazione
      // ==================================================================================================================================             
      manageJwtAuthOutbound();
      
      // ==================================================================================================================================
      // Gestisce custom request headers
      // ==================================================================================================================================
      manageCustomHeaders();
      
      // ==================================================================================================================================
      // Gestisce debugging properties
      // ==================================================================================================================================
      manageDebuggingProperties();

      // ==================================================================================================================================
      // Gestisce logging informativo
      // ==================================================================================================================================
      try {
         // Genera logging di sintesi della asserzione
         Logger.logMessage(LogLevel.INFO,"Outbound (JWT) => "+StringUtils.replaceTemplates(Context,Config.getString(LOGGING_INFO)));
      } catch (Exception ObjException) {
         String StrError = "Logging info error";
         Logger.logMessage(LogLevel.WARN,StrError,ObjException);
      }       
   }

   // ==================================================================================================================================
   // Gestisce autenticazione JWT outbound
   // ==================================================================================================================================      
   protected void manageJwtAuthOutbound() throws TransportException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();      
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"JWT AUTH");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
             
      // ==================================================================================================================================
      // Prepara autenticazione
      // ==================================================================================================================================   
      prepareAuthentication();
             
      // ==================================================================================================================================      
      // Prepara resource
      // ==================================================================================================================================
      prepareAuthorization();
        
      // ==================================================================================================================================
      // Prepara access token
      // ==================================================================================================================================

      // Acquisisce access token
      prepareAccessToken();
      
      // Imposta l'header di autenticazione con l'access token ottenuto
      JWTProvider ObjToken = (JWTProvider) Context.get("token");
      HttpURLConnection ObjRequest =  (HttpURLConnection) Context.get("http.request");
      ObjRequest.setRequestProperty("Authorization", "Bearer " + ObjToken.serialize());
   }
   
   // ==================================================================================================================================
   // Gestisce custom request headers
   // ==================================================================================================================================
   protected void manageCustomHeaders() throws TransportException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();  
      
      // Variabili di lavoro
      XmlObject ObjHeaderSecrets = null;
      String StrHeaderSecretsParsedPath = "";
      Properties ObjRequestHeaders = new Properties();
      
      // Genera banner di sezione
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"CUSTOM HEADERS");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         
      // Acquisisce gli header della configurazione statica del provider
      if (Config.getProperties(CUSTOM_REQUEST_HEADERS)!=null) 
         ObjRequestHeaders.putAll(Config.getProperties(CUSTOM_REQUEST_HEADERS));

      // Acquisisce gli header definiti nelle policy di sicurezza
      CustomHeaders ObjPolicyHeaders = (CustomHeaders) Context.get("policy_custom_headers");

      // Se presenti integra gli header delle policy (prevalgono su quelli statici)
      if (ObjPolicyHeaders!=null) {
         for (String StrHeaderName : ObjPolicyHeaders.keySet()) {
            CustomHeader ObjHeader = ObjPolicyHeaders.get(StrHeaderName);

            // Se non è un header "secure" esegue, altrimenti procede
            if (!ObjHeader.secure) {
               ObjRequestHeaders.setProperty(StrHeaderName,ObjHeader.value);
            } else {
               try {
                  
                  // Se è il primo secure header acquisisce service account di mapping per i secret
                  if (StrHeaderSecretsParsedPath.isEmpty()) {
                     StrHeaderSecretsParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_HEADER_SECRETS_PATH));
                     Logger.logProperty(LogLevel.DEBUG,"Header Secrets Path",StrHeaderSecretsParsedPath);
                     ObjHeaderSecrets = OSBUtils.getResourceCached("ServiceAccount",StrHeaderSecretsParsedPath);                           
                  }
                  
                  // Trasla gli eventuali template del valore e cerca segreto associato nel service account di mapping
                  String StrHeaderSecretKey = StringUtils.replaceTemplates(Context,ObjHeader.value);
                  String StrHeaderSecret = XMLUtils.getTextValue(ObjHeaderSecrets,"//*:remote-user[*:username/text()='"+StrHeaderSecretKey+"']/*:password/text()");

                  // Se il segreto non e' disponibile genera eccezione
                  if (StrHeaderSecret.isEmpty()) throw new Exception("secret not found for key '"+StrHeaderSecretKey+"'");

                  // Imposta il valore tradotto
                  ObjRequestHeaders.setProperty(StrHeaderName,StrHeaderSecret);

               } catch (Exception ObjException) {
                  String StrError = "Secure header error ('"+StrHeaderName+"')";
                  Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
                  throw new TransportException(StrError);
               }
            }
         }
      }

      // Se presenti applica i custom header alla request
      if (!ObjRequestHeaders.isEmpty()) manageCustomHeaders(ObjRequestHeaders,null,false);   
   }   
   
   // ==================================================================================================================================
   // Completa parsing, validazione e traduzione delle policy
   // ==================================================================================================================================
   protected void preparePolicies() throws TransportException {
    
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();
      
      // ==================================================================================================================================
      // Acquisisce policy di sicurezza globali e seleziona i livelli applicabili (endpoint, progetto, profilo)
      // ==================================================================================================================================   

      // Prepara variabili di lavoro
      XmlObject ObjDefaultPolicies = null;
      XmlObject ObjProfilePolicies = null;
      XmlObject ObjProjectPolicies = null;
      XmlObject ObjEndpointPolicies = null;
      ArrayList<XmlObject> ArrLevelPolicies = new ArrayList<XmlObject>();
                  
      try {

         // Valida e acquisisce il file delle policy di sicurezza (accede direttamente alla configurazione MBEAN perchè la config non è ancora inizializzabile)
         XmlObject ObjGlobalPolicies = validateResource(getProviderMBean().getJWT_POLICIES_PATH());
         
         // Estrapola le policy di default
         ObjDefaultPolicies = ObjGlobalPolicies.selectPath("/outboundPolicies/defaults")[0];
         
         // Estrapola le eventuali policy a livello di endpoint
         TransportEndPoint ObjEndpoint = (TransportEndPoint) Context.get("osb.endpoint");
         XmlObject[] ArrEndpointPolicies = ObjGlobalPolicies.selectPath("/outboundPolicies/endpoints/item[@name='"+ObjEndpoint.getServiceRef().getLocalName()+"']");         
         if (ArrEndpointPolicies.length==1) ObjEndpointPolicies = ArrEndpointPolicies[0];
         
         // Estrapola le eventuali policy a livello di progetto
         XmlObject[] ArrProjectPolicies = ObjGlobalPolicies.selectPath("/outboundPolicies/projects/item[@name='"+ObjEndpoint.getServiceRef().getProjectName()+"']");         
         if (ArrProjectPolicies.length==1) ObjProjectPolicies = ArrProjectPolicies[0];
         
         // Determina il profilo da applicare (quello dell'endpoint prevale su quello del progetto)
         String StrProfile = null;
         boolean BolEndpointProfile = false;
         
         if (ObjEndpointPolicies!=null) {
            StrProfile = XMLUtils.getAttributeValue(ObjEndpointPolicies,"profile",null);   
            BolEndpointProfile = (StrProfile!=null);
         }
         
         if ((ObjProjectPolicies!=null)&&(StrProfile==null)) 
            StrProfile = XMLUtils.getAttributeValue(ObjProjectPolicies,"profile",null);   
         
         // Estrapola le eventuali policy a livello di profilo
         if (StrProfile!=null) ObjProfilePolicies = ObjGlobalPolicies.selectPath("/outboundPolicies/profiles/item[@name='"+StrProfile+"']")[0];
         
         // Compone i livelli in ordine di precedenza decrescente (il profilo segue il livello che lo dichiara)
         if (ObjEndpointPolicies!=null) ArrLevelPolicies.add(ObjEndpointPolicies);
         if (BolEndpointProfile) ArrLevelPolicies.add(ObjProfilePolicies);
         if (ObjProjectPolicies!=null) ArrLevelPolicies.add(ObjProjectPolicies);
         if ((ObjProfilePolicies!=null)&&(!BolEndpointProfile)) ArrLevelPolicies.add(ObjProfilePolicies);
         ArrLevelPolicies.add(ObjDefaultPolicies);
                  
      } catch (Exception ObjException) {
         String StrError = "Error while parsing security policies";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);         
      }
   
      // Logging policies
      if (Logger.checkLogLevel(LogLevel.TRACE)) {
         Logger.logProperty(LogLevel.TRACE,"Default Policies",linearizeXml(ObjDefaultPolicies));
         Logger.logProperty(LogLevel.TRACE,"Profile Policies",linearizeXml(ObjProfilePolicies));
         Logger.logProperty(LogLevel.TRACE,"Project Policies",linearizeXml(ObjProjectPolicies));
         Logger.logProperty(LogLevel.TRACE,"Endpoint Policies",linearizeXml(ObjEndpointPolicies));
      }
   
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Consolida attributi
      // ----------------------------------------------------------------------------------------------------------------------------------

      // Acquisice parametri sicurezza
      for (String StrAttributeName : Arrays.asList("provider","identity","method","scope","resource","resource_mapped",
                                                   "secret_request","assertion_request","assertion_token",
                                                   "token_cache_ttl","token_cache_index")) {

         String StrAttributeValue = null;
            
         // Scandisce i livelli in ordine di precedenza decrescente e si ferma al primo che definisce l'attributo
         for (XmlObject ObjLevelPolicies : ArrLevelPolicies) {
            StrAttributeValue = XMLUtils.getAttributeValue(ObjLevelPolicies,StrAttributeName,null);
            if (StrAttributeValue!=null) break;
         }

         Context.put(StrAttributeName,StrAttributeValue);
         Logger.logProperty(LogLevel.DEBUG,"Policy Attribute",StrAttributeName+" => "+StrAttributeValue);
      }
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Consolida custom headers
      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Acquisisce, valida e sintetizza i custom headers
      CustomHeaders ObjCustomHeaders = new CustomHeaders();
      
      try {
         // Scandisce i livelli in ordine di precedenza crescente (prevale l'ultimo che definisce l'header)
         for (int IntIndex=ArrLevelPolicies.size()-1;IntIndex>=0;IntIndex--) {
            
            XmlObject ObjLevelPolicies = ArrLevelPolicies.get(IntIndex);
            
            prepareHeader(ObjCustomHeaders,ObjLevelPolicies,"customHeader");
            prepareHeader(ObjCustomHeaders,ObjLevelPolicies,"customHeader","value");            
            prepareHeader(ObjCustomHeaders,ObjLevelPolicies,"secureHeader");
            prepareHeader(ObjCustomHeaders,ObjLevelPolicies,"secureHeader","key");
         }          
      } catch (Exception ObjException) {
         String StrError = "Error in security policies custom headers ("+ObjException.getMessage()+")";
         Logger.logMessage(LogLevel.ERROR,StrError);
         throw new TransportException(StrError);         
      }                     
      
      // Aggiorna context con custom headers
      Context.put("policy_custom_headers",ObjCustomHeaders);
      
      // Se necessario genera logging dei custom headers
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         for (String StrHeaderName : ObjCustomHeaders.keySet()) {
            CustomHeader ObjHeader = ObjCustomHeaders.get(StrHeaderName);
            Logger.logProperty(LogLevel.DEBUG,"Policy Custom Header",((ObjHeader.secure)?("(secure) "):("(normal) "))+StrHeaderName+" => "+ObjHeader.value);
         }
      }  
            
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Risolve i template
      // ----------------------------------------------------------------------------------------------------------------------------------
            
      try {

         // Acquisisce il file dei template
         String StrTemplatesPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_TEMPLATES_PATH));
         Logger.logProperty(LogLevel.DEBUG,"Templates Path",StrTemplatesPath);
         XmlObject ObjTemplates = validateResource(StrTemplatesPath);
         
         // Risolve gli identitificativi dei template e li mette nel context
         XmlObject ObjTokenTemplate = null;
         XmlObject ObjRequestTemplate = null;
         
         if (Context.get("method").equals("secret")) {
            ObjRequestTemplate = ObjTemplates.selectPath("/outboundTemplates/request[@name='"+Context.getString("secret_request")+"' and @method='secret']")[0];
         } else {
            ObjTokenTemplate = ObjTemplates.selectPath("/outboundTemplates/token[@name='"+Context.getString("assertion_token")+"' and @type='client_assertion']")[0];
            ObjRequestTemplate = ObjTemplates.selectPath("/outboundTemplates/request[@name='"+Context.getString("assertion_request")+"' and @method='assertion']")[0];            
         }

         // Logging templates
         if (Logger.checkLogLevel(LogLevel.TRACE)) {
            Logger.logProperty(LogLevel.TRACE,"Token Template",linearizeXml(ObjTokenTemplate));
            Logger.logProperty(LogLevel.TRACE,"Request Template",linearizeXml(ObjRequestTemplate));
         }
         
         // Estrapola dal template di request la token url
         Context.put("token_template",ObjTokenTemplate);
         Context.put("request_template",ObjRequestTemplate);         
         Context.put("token_url",XMLUtils.getAttributeValue(ObjRequestTemplate,"tokenURL",null));
         
      } catch (Exception ObjException) {
         String StrError = "Error while parsing templates";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);         
      }
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Acquisisce il mapping delle risorse
      // ----------------------------------------------------------------------------------------------------------------------------------
            
      try {

         // Se presenti rimpiazza i template nel path della risorsa osb
         String StrResourceMappingParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_RESOURCE_MAPPING_PATH));
         Logger.logProperty(LogLevel.DEBUG,"Resource Mapping Path",StrResourceMappingParsedPath);
   
         // Valida e acquisisce il file xml per il mapping delle risorse e lo mette nel context
         Context.put("resource_mappings",validateResource(StrResourceMappingParsedPath));
         
      } catch (Exception ObjException) {
         String StrError = "Error while parsing resource mappings";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);         
      }
   }

   // ==================================================================================================================================
   // Costruisce claims da token template 
   // ==================================================================================================================================
   protected JWTClaimsMap prepareClaims(XmlObject ObjTokenTemplate) throws Exception {

      JWTClaimsMap ObjResult = new JWTClaimsMap();
      
      XmlObject[] ArrClaims = ObjTokenTemplate.selectPath("./claim");      
      for (int IntIndex = 0; IntIndex < ArrClaims.length; IntIndex++) { 
         
         String StrName = XMLUtils.getAttributeValue(ArrClaims[IntIndex],"name",null);
         String StrType = XMLUtils.getAttributeValue(ArrClaims[IntIndex],"type",null);
         String StrValue = XMLUtils.getTextValue(ArrClaims[IntIndex],".");
         
         if ("String".equals(StrType)) StrValue = "'"+StringUtils.escapeJavaScript(StrValue)+"'";         
         ObjResult.put(StrName,evaluateScript(StrValue,StrType));
      }
      return ObjResult;
   }

   // ==================================================================================================================================
   // Costruisce x-www-form-urlencoded da request template
   // ==================================================================================================================================
   protected String prepareRequest(XmlObject ObjTokenTemplate) throws Exception {
      
      StringBuilder ObjResult = new StringBuilder();
      XmlObject[] ArrClaims = ObjTokenTemplate.selectPath("./parameter"); 
      
      for (int IntIndex = 0; IntIndex < ArrClaims.length; IntIndex++) {    
         
         String StrName = XMLUtils.getAttributeValue(ArrClaims[IntIndex],"name",null);
         String StrType = XMLUtils.getAttributeValue(ArrClaims[IntIndex],"type",null);
         String StrValue = XMLUtils.getTextValue(ArrClaims[IntIndex],".");   
         
         if ("String".equals(StrType)) StrValue = "'"+StringUtils.escapeJavaScript(StrValue)+"'";         
         StrValue = String.valueOf(evaluateScript(StrValue,StrType));

         if (IntIndex > 0) {
            ObjResult.append("&");
         }

         ObjResult.append(URLEncoder.encode(StrName, StandardCharsets.UTF_8.name()))
                  .append("=")
                  .append(URLEncoder.encode(StrValue, StandardCharsets.UTF_8.name()));
      }

      return ObjResult.toString();
   }   
   
   // ==================================================================================================================================
   // Prepara autenticazione in base al metodo
   // ==================================================================================================================================            
   protected void prepareAuthentication() throws TransportException {
      
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();  
       
      // Acquisisce context
      String StrMETHOD = Context.getString("method");
      String StrPROVIDER = Context.getString("provider");
      String StrIDENTITY = Context.getString("identity");

      try {               
          
         // Risolve eventuali template dell'identity e riaggiorna il context
         StrIDENTITY = StringUtils.replaceTemplates(Context,StrIDENTITY);
         Context.put("identity",StrIDENTITY);

         // Mappa l'identita' al client_id mediante il mapping delle risorse e aggiorna context
         Context.put("client_id",translateResource((XmlObject)Context.get("resource_mappings"),StrPROVIDER,StrIDENTITY));
         Logger.logProperty(LogLevel.DEBUG,"Client ID",Context.getString("client_id"));

         // Gestisce specificità in base al metodo
         if (StrMETHOD.equals("secret")) {
            
            // Se presenti rimpiazza i template nel path della risorsa osb
            String StrClientSecretsParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_CLIENT_SECRETS_PATH));            
            Logger.logProperty(LogLevel.DEBUG,"Client Secret Path",StrClientSecretsParsedPath);
            
            // Acquisisce il service account dei secret e cerca il secret associato a provider e identita'
            XmlObject ObjClientSecrets = OSBUtils.getResourceCached("ServiceAccount",StrClientSecretsParsedPath);
            String StrClientSecret = XMLUtils.getTextValue(ObjClientSecrets,"//*:remote-user[*:username/text()='"+StrPROVIDER+":"+StrIDENTITY+"']/*:password/text()");

            // Se il secret non e' disponibile genera eccezione
            if (StrClientSecret.isEmpty()) throw new Exception("secret not found");

            // Aggiorna context
            Context.put("client_secret",StrClientSecret);
                   
         } else {
                   
            // Se presenti rimpiazza i template nel path della risorsa osb
            String StrClientKeysParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_CLIENT_KEYS_PATH));            
            Logger.logProperty(LogLevel.DEBUG,"Client Keys Path",StrClientKeysParsedPath);
            
            // Acquisisce la chiave privata dell'identita' mediante la risorsa OSB di tipo XML
            XmlObject ObjClientKey = 
               validateResource(StrClientKeysParsedPath).selectPath(
                  "/clientKeys/item[@provider='"+StrPROVIDER+"' and @identity='"+StrIDENTITY+"']")[0];
            
            // Crea un assertion token
            JWTProvider ObjClientAssertionToken =
               prepareToken().build(prepareClaims((XmlObject)Context.get("token_template")),
                                    XMLUtils.getTextValue(ObjClientKey, "./@alg"),
                                    XMLUtils.getTextValue(ObjClientKey, "./@kid"),                                    
                                    XMLUtils.getTextValue(ObjClientKey, "./text()"),
                                    WLSUtils.decryptionHelper(XMLUtils.getTextValue(ObjClientKey, "./@password")));
            
            // Aggiorna context
            Context.put("client_assertion",ObjClientAssertionToken.serialize());      
         }
      } catch (Exception ObjException) {
         String StrError = "Identity mapping error ("+StrPROVIDER+":"+StrIDENTITY+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);
      }
   }
   
   // ==================================================================================================================================      
   // Prepara resource gestendo il mapping delle risorse
   // ==================================================================================================================================
   protected void prepareAuthorization() throws TransportException {
      
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();      

      // Acquisisce variabili di contesto
      String StrPROVIDER = Context.getString("provider");
      String StrMAPPING = Context.getString("resource_mapped","true");
      String StrRESOURCE = Context.getString("resource");
      String StrSCOPE = Context.getString("scope");
                 
      try {

         // Trasla eventiali template di resource
         StrRESOURCE = StringUtils.replaceTemplates(Context,StrRESOURCE);

         // Se la risorsa è impostata e va gestito il mapping esegue
         if ((!StrRESOURCE.isEmpty())&&(StrMAPPING.equals("true"))) {
            
            // Traduce la risorsa mediante il mapping delle risorse
            StrRESOURCE = translateResource((XmlObject)Context.get("resource_mappings"),StrPROVIDER,StrRESOURCE);
         }
         
         // Aggiorna context
         Context.put("resource",StrRESOURCE);
         
      } catch (Exception ObjException) {
         String StrError = "Resource error ("+StrRESOURCE+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);
      }                   
    
      try {

         // Trasla eventuali template di scope e aggiorna context
         Context.put("scope",StringUtils.replaceTemplates(Context,StrSCOPE));                     
         
      } catch (Exception ObjException) {
         String StrError = "Scope error ("+StrSCOPE+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);
      }  
   }
   
   // ==================================================================================================================================
   // Gestisce preparazione access token per jwt outbund
   // ==================================================================================================================================
   protected void prepareAccessToken() throws TransportException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
   
      try {
         
         // Prepara l'identificativo univoco dell'access token
         String StrTokenID = StringUtils.replaceTemplates(Context,Context.getString("token_cache_index"));
      
         // Cerca un access token valido per il contesto nella cache
         JWTTokensCacheEntry ObjCachedToken = ObjProviderContext.jwtCache.getToken(StrTokenID,Integer.parseInt(Context.getString("token_cache_ttl")));
               
         // Se il token non è in cache esegue
         if (ObjCachedToken==null) {
                     
            // ----------------------------------------------------------------------------------------------------------------------------------
            // Esegue lo stacco del token di accesso
            // ----------------------------------------------------------------------------------------------------------------------------------
            
            // Genera logging
            Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
            Logger.logMessage(LogLevel.DEBUG,"ACCESS TOKEN REQUEST");
            Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
                      
            // Prepara request per l'access token
            String StrRequest = prepareRequest((XmlObject)Context.get("request_template"));
   
            // Genera logging
            Logger.logProperty(LogLevel.TRACE,"Request",StrRequest);
                      
            // Acquisisce l'accesso token
            String StrResponse = fetchResource(HttpMethod.POST,
                                              Context.getString("token_url"),
                                              StrRequest.getBytes(StandardCharsets.UTF_8),
                                              "application/x-www-form-urlencoded","application/json",
                                              "ANONYMOUS", "", "", 
                                              Logger);
   
            // Genera logging
            Logger.logProperty(LogLevel.TRACE,"Response",StrResponse);
   
            // Acquisisce payload in formato json e genera logging
            JSONObject ObjJSON = new JSONObject(StrResponse);
                     
            // Inizializza il token jwt
            JWTProvider ObjJwtAccessToken = prepareToken(ObjJSON.getString("access_token")); 
            
            // Salva il token in cache
            ObjCachedToken = ObjProviderContext.jwtCache.putToken(StrTokenID,ObjJwtAccessToken);
         }   
         
         // Aggiorna il riferimento al token nel context
         Context.put("token",ObjCachedToken.token);      
             
      } catch (Exception ObjException) {
            
         String StrMessage = "";
         
         if ((ObjException instanceof HttpStatusException)&& 
             ((HttpStatusException)ObjException).contentType.startsWith("application/json")) {

            HttpStatusException ObjStatusExpection = (HttpStatusException) ObjException;

            JSONObject ObjJSON = new JSONObject(ObjStatusExpection.body);
            StrMessage = ObjJSON.optString("error_description").replaceAll("\\s*[\\r\\n]+\\s*"," ");
         }
                        
         String StrError = "Error while preparing access token"+(StrMessage.isEmpty()?(""):(" ("+StrMessage+")"));
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new TransportException(StrError);         
      }      
   }
   
   // ==================================================================================================================================
   // Convert string array with key/value pairs to x-www-form-urlencoded
   // ==================================================================================================================================
   protected String encodeProperties(String[] ArrKeyValues) throws Exception {
      
      // Prepara string builder
      StringBuilder ObjResult = new StringBuilder();

      // Esegue ciclo su ogni coppia chiave:valore
      for (int IntIndex = 0; IntIndex < ArrKeyValues.length; IntIndex++) {
         String StrKeyValue = ArrKeyValues[IntIndex];
         if (StrKeyValue == null || StrKeyValue.isEmpty()) {
            continue;
         }

         // Separa chiave e valore
         String[] ArrParts = StrKeyValue.split(":",2);
         if (ArrParts.length!=2) {
            throw new Exception("invalid key-value pair '" + StrKeyValue + "'");
         }

         // Prepara chiave e valore risolvendo eventuali template ed eseguendo l'eventuale scripting
         String StrKey = ArrParts[0].trim();
         String StrValue = String.valueOf(evaluateScript(ArrParts[1].trim(),"String","Integer"));

         // Codifica chiave e valore secondo application/x-www-form-urlencoded
         if (IntIndex > 0) {
            ObjResult.append("&");
         }

         ObjResult.append(URLEncoder.encode(StrKey, StandardCharsets.UTF_8.name()))
                  .append("=")
                  .append(URLEncoder.encode(StrValue, StandardCharsets.UTF_8.name()));
      }

      // Restituisce query string
      return ObjResult.toString();
   }
   
   // ==================================================================================================================================
   // Determina l'operazione outbound e popola il context (osb.context, osb.outbound, osb.operation)
   // ==================================================================================================================================
   protected void detectOperation(TransportEndPoint ObjEndpoint,TransportSender ObjSender) {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();

      // Variabili di lavoro
      String StrOperation = "";
      String StrOperationSource = "";
      String StrOperationMessage = "";
      
      MessageContext ObjMessageContext = null;
      OutboundEndpoint ObjOutboundContext = null;
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Se la chiamata proviene da una pipeline acquisisce il message context e ricava l'operazione da $outbound o $operation
      // ----------------------------------------------------------------------------------------------------------------------------------
      try {

         // Risale dal transformer del sender al message context della pipeline
         PipelineContext ObjPipelineContext = (PipelineContext) JavaUtils.getField(ObjSender.getTransformer(),"this$0");
         RouterCallback ObjRouterCallback = (RouterCallback) ObjPipelineContext.getProperty("ROUTING_CALLBACK");
         RouterContext ObjRouterContext = (RouterContext) JavaUtils.getField(ObjRouterCallback,"_context");
         ObjMessageContext = ObjRouterContext.getMessageContext();
         ObjOutboundContext = ObjMessageContext.getOutbound();
         
         // Estrae l'operazione da $outbound (service/operation) o ripiega su $operation
         // Equivale a fare xpath su "$outbound/ctx:service/ctx:operation" che però in alcuni casi va in eccezione
         if (ObjOutboundContext!=null) {
            com.bea.wli.sb.context.ServiceInfo ObjServiceInfo = ObjOutboundContext.getServiceInfo();
            String StrOutboundOperation = (ObjServiceInfo!=null)?(ObjServiceInfo.getOperation()):(null);
            StrOperation = (StrOutboundOperation!=null)?(StrOutboundOperation):("");
         }

         if (!StrOperation.isEmpty()) {
            StrOperationSource = "message context ($outbound)"; 
         } else {
            String StrOutboundOperation = ObjMessageContext.getOperation();
            StrOperation = (StrOutboundOperation!=null)?(StrOutboundOperation):("");
            
            if (!StrOperation.isEmpty()) {
               StrOperationSource = "message context ($operation)"; 
            } else {
               StrOperationSource = "wsdl fallback (invalid message context)"; 
            }
         }

      } catch (NoSuchFieldException ObjException) {

         // Nessuna pipeline (es. invocazione diretta del business service dalla test console)
         StrOperationSource = "wsdl fallback (missing message context)";

      } catch (Exception ObjException) {
         Logger.logMessage(LogLevel.WARN,"Cannot access message context",ObjException);
      }

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Se l'operazione non e' determinata e il servizio e' SOAP con WSDL prova a ricavarla dalla SOAPAction
      // ----------------------------------------------------------------------------------------------------------------------------------
      if (StrOperation.isEmpty()) {
         try {

            // Acquisisce il WSDL effettivo del business service e il binding selezionato
            EffectiveWSDL ObjEffectiveWSDL = CommonServiceRepository.getEffectiveWSDL(ObjEndpoint.getServiceRef());
            WsdlBinding ObjBinding = ((ObjEffectiveWSDL!=null)&&(!ObjEffectiveWSDL.isInError()))?(ObjEffectiveWSDL.getBinding()):(null);

            // Verifica che si tratti di un binding SOAP (1.2 oppure 1.1)
            boolean BolSoap12 = (ObjBinding!=null)&&(Soap12Binding.narrow(ObjBinding)!=null);
            boolean BolSoap11 = (ObjBinding!=null)&&(!BolSoap12)&&(SoapBinding.narrow(ObjBinding)!=null);

            if (!BolSoap11&&!BolSoap12) {
               StrOperationMessage = "not a SOAP service";
            } else {

               // Acquisisce la SOAPAction dalla request (header per SOAP 1.1, parametro action del Content-Type per SOAP 1.2)
               RequestHeaders ObjHeaders = ObjSender.getMetaData().getHeaders();
               String StrSoapAction = null;

               if (BolSoap12) {
                  Object ObjContentType = ObjHeaders.getHeader("Content-Type");
                  if (ObjContentType!=null) {
                     Matcher ObjMatcher = Pattern.compile("(?i)[;\\s]action\\s*=\\s*\"?([^\";]*)\"?").matcher(ObjContentType.toString());
                     if (ObjMatcher.find()) StrSoapAction = ObjMatcher.group(1);
                  }
               } else {
                  Object ObjSoapAction = ObjHeaders.getHeader("SOAPAction");
                  if (ObjSoapAction!=null) StrSoapAction = ObjSoapAction.toString();
               }

               // Normalizza la SOAPAction (trim e rimozione degli apici)
               StrSoapAction = (StrSoapAction==null)?(""):(StrSoapAction.trim().replaceAll("^\"|\"$",""));

               // Scandisce le operazioni del binding e raccoglie quelle con la stessa soapAction
               ArrayList<String> ArrMatches = new ArrayList<String>();
               ArrayList<String> ArrOperations = new ArrayList<String>();

               for (WsdlBindingOperation ObjOperation : ObjBinding.getOperations().values()) {

                  SoapBindingOperation ObjSoapOperation =
                     (BolSoap12)?(Soap12BindingOperation.narrow(ObjOperation)):(SoapBindingOperation.narrow(ObjOperation));

                  String StrOperationAction =
                     ((ObjSoapOperation==null)||(ObjSoapOperation.getSoapAction()==null))?(""):(ObjSoapOperation.getSoapAction().trim().replaceAll("^\"|\"$",""));

                  ArrOperations.add(ObjOperation.getName().getLocalPart());
                  if (StrOperationAction.equals(StrSoapAction)) ArrMatches.add(ObjOperation.getName().getLocalPart());
               }

               // Se il match e' univoco lo utilizza, altrimenti ripiega sull'unica operazione del binding se ce n'e' una sola
               if (ArrMatches.size()==1) {
                  StrOperation = ArrMatches.get(0);
                  StrOperationMessage = "wsdl lookup by soapAction";
               } else if (ArrOperations.size()==1) {
                  StrOperation = ArrOperations.get(0);
                  StrOperationMessage = "wsdl single operation binding";
               } else if (ArrMatches.isEmpty()) {
                  StrOperationMessage = "no wsdl operation matches soapAction";
               } else {
                  StrOperationMessage = "multiple wsdl operation matches soapAction";
               }
            }

         } catch (NotFoundException ObjException) {

            // Il servizio non e' basato su WSDL
            StrOperationMessage = "not a WSDL based service";

         } catch (Exception ObjException) {
            Logger.logMessage(LogLevel.WARN,"Cannot resolve operation from wsdl",ObjException);
         }
      }

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Aggiorna context
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("osb.context",ObjMessageContext);
      Context.put("osb.outbound",ObjOutboundContext);
      
      Context.put("osb.operation",StrOperation);
      Context.put("osb.operation.source",StrOperationSource);
      Context.put("osb.operation.message",StrOperationMessage);
   }

   // ==================================================================================================================================
   // Crea nuova configurazione di thread in modalità outbound
   // ==================================================================================================================================    
   protected RuntimeConfig createConfig() {   
      
      // Prepara nuova config
      RuntimeConfig Config = super.createConfig();     
      
      Config.put(PROVIDER_TYPE,getProviderMBean().getPROVIDER_TYPE());      
      
      Config.put(LOGGING_LINES,getProviderMBean().getLOGGING_LINES());            
      Config.put(LOGGING_LEVEL,getProviderMBean().getLOGGING_LEVEL());
      Config.put(LOGGING_INFO,getProviderMBean().getLOGGING_INFO());
      Config.put(THREADING_MODE,getProviderMBean().getTHREADING_MODE());
      
      Config.put(REQUESTS_PROXY_MODE,getProviderMBean().getREQUESTS_PROXY_MODE());
      Config.put(REQUESTS_PROXY_PATH,getProviderMBean().getREQUESTS_PROXY_PATH());      
      Config.put(REQUESTS_SSL_VERIFY,getProviderMBean().getREQUESTS_SSL_VERIFY());
      Config.put(REQUESTS_CONN_TIMEOUT,getProviderMBean().getREQUESTS_CONN_TIMEOUT());
      Config.put(REQUESTS_READ_TIMEOUT,getProviderMBean().getREQUESTS_READ_TIMEOUT());
      
      Config.put(JWT_POLICIES_PATH,getProviderMBean().getJWT_POLICIES_PATH());
      Config.put(JWT_TEMPLATES_PATH,getProviderMBean().getJWT_TEMPLATES_PATH());
      Config.put(JWT_CLIENT_KEYS_PATH,getProviderMBean().getJWT_CLIENT_KEYS_PATH());     
      Config.put(JWT_CLIENT_SECRETS_PATH,getProviderMBean().getJWT_CLIENT_SECRETS_PATH());
      Config.put(JWT_HEADER_SECRETS_PATH,getProviderMBean().getJWT_HEADER_SECRETS_PATH());      
      Config.put(JWT_RESOURCE_MAPPING_PATH,getProviderMBean().getJWT_RESOURCE_MAPPING_PATH());      
                  
      Config.put(CUSTOM_REQUEST_HEADERS,getProviderMBean().getCUSTOM_REQUEST_HEADERS());
      
      Config.put(DEBUGGING_ASSERTION,getProviderMBean().getDEBUGGING_ASSERTION());
      Config.put(DEBUGGING_PROPERTIES,getProviderMBean().getDEBUGGING_PROPERTIES());
      
      // Prepara livelli di logging di default
      LogManager Logger = getLogger();
      Logger.setLogLines(Config.getInteger(LOGGING_LINES));
      Logger.setLogLevel(Config.getString(LOGGING_LEVEL));
      
      return Config;   
   } 
   
   // ==================================================================================================================================
   // Crea nuovo context di thread in modalità outbound
   // ==================================================================================================================================    
   protected RuntimeContext createContext(TransportEndPoint ObjEndpoint,TransportSender ObjSender,HttpURLConnection ObjConnection) {   

      // Acquisisce logger & config
      LogManager Logger = getLogger();  
      
      // Prepara parametri business service di outbound
      ServiceInfo ObjService = new ServiceInfo(ObjEndpoint.getServiceRef(), ObjEndpoint.getConfiguration(),null);

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto condivise
      // ----------------------------------------------------------------------------------------------------------------------------------
      RuntimeContext Context = super.createContext("outbound",ObjService);

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto statiche (ad uso interno, non utilizzabili come template)
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("osb.sender",ObjSender);    
      Context.put("osb.endpoint",ObjEndpoint);    
      Context.put("http.request",ObjConnection);
      
      try {
         RequestMetaData ObjRequestMetadata = ObjSender.getMetaData();
         Context.put("http.header",ObjRequestMetadata.getHeaders());    
         Context.put("osb.metadata",ObjRequestMetadata.getUserMetaData()); 
      } catch (Exception ObjException) {
         Logger.logMessage(LogLevel.ERROR,"Cannot access request metadata",ObjException);
      }
      
      // Determina il message context (se disponibile) e l'operazione outbound
      detectOperation(ObjEndpoint,ObjSender);

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche semplici
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("username",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            TransportSender ObjSender = (TransportSender) ObjContext.get("osb.sender");            
            SecurityContext ObjSecurityContext = (SecurityContext) JavaUtils.getField(ObjSender.getCredentialCallback(),"_securityContext");                     
            return ObjSecurityContext.getTransportContext().getUsernamePassword().getUsername();
         }
      });  
      
      Context.put("http.content.body",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            TransportSender ObjSender = (TransportSender) ObjContext.get("osb.sender");
            return ObjSender.getPayload().toString();
         }
      });   
      Context.put("http.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            Map<String,Object> ObjHeaders = OSBUtils.buildRequestHeaders((RequestHeaders)ObjContext.get("http.header"));
            return Logger.formatProperties(LogLevel.DEBUG,ObjHeaders,StringUtils.repeat(90,"-"),false);
         }
      });  
      
      Context.put("osb.metadata.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            Map<String,Object> ObjMetadata = (Map<String,Object>) ObjContext.get("osb.metadata");
            return Logger.formatProperties(LogLevel.DEBUG,ObjMetadata,StringUtils.repeat(90,"-"),false);
         }
      });       
      Context.put("osb.context.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            
            MessageContext ObjMessageContext = (MessageContext) ObjContext.get("osb.context");
            if (ObjMessageContext==null) return "";
            
            LogManager Logger = getLogger();
            Map<String,Object> ObjVariables = OSBUtils.buildContextVariables(ObjMessageContext);
            return Logger.formatProperties(LogLevel.DEBUG,ObjVariables,StringUtils.repeat(90,"-"),false);
         }
      }); 
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche regex
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.putRegex("^http\\.header\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            RequestHeaders ObjHeaders = (RequestHeaders) ObjContext.get("http.header");
            return (String) ObjHeaders.getHeader(StrVariableName.split("\\.")[2]); 
         }
      });
      Context.putRegex("^osb\\.metadata\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            Map<String,Object> ObjMetadata = (Map<String,Object>) ObjContext.get("osb.metadata");
            return (String) ObjMetadata.get(StrVariableName.split("\\.")[2]);  
         }
      });
      Context.putRegex("^osb\\.context\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            MessageContext ObjMessageContext = (MessageContext) ObjContext.get("osb.context");
            return (ObjMessageContext==null)?(""):(ObjMessageContext.getVariableValue(StrVariableName.split("\\.")[2]).toString());
         }
      });
      // ----------------------------------------------------------------------------------------------------------------------------------

      return Context;   
   } 

   // ==================================================================================================================================
   // Acquisisce provider
   // ==================================================================================================================================    
   protected CustomOutboundAuthenticatorMBean getProviderMBean() {
      return (CustomOutboundAuthenticatorMBean) ObjProviderContext.providerMBean;
   }
}
