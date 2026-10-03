// ##################################################################################################################################
// VERSIONING
// ##################################################################################################################################
// $Revision: 2057 $
// $Date: 2026-10-02 21:43:20 +0200 (Fri, 02 Oct 2026) $
// ##################################################################################################################################

package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import java.util.List;
import java.util.Arrays;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;

import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;
import weblogic.management.security.ProviderMBean;

import com.bea.wli.sb.services.ServiceInfo;
import com.bea.wli.sb.transports.TransportEndPoint;

import org.json.XML;
import org.json.JSONObject;
import org.apache.xmlbeans.XmlObject;

import org.falpi.*;
import org.falpi.utils.*;
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.StringUtils.*;
import org.falpi.utils.jwt.*;
import org.falpi.utils.jwt.JWTCache.*;
import org.falpi.utils.logging.*;

// ##################################################################################################################################
// Classe principale
// ##################################################################################################################################

public class CustomInboundAuthenticator extends CustomAuthenticator implements AuthenticationProviderV2, IdentityAsserterV2 {
   
   // ##################################################################################################################################
   // Costanti 
   // ##################################################################################################################################
   
   // Identificativi dei parametri di configurazione
   public static final String BASIC_AUTH                = "BASIC_AUTH";
   public static final String JWT_AUTH                  = "JWT_AUTH";
   public static final String JWT_POLICIES_PATH         = "JWT_POLICIES_PATH";
   public static final String JWT_RESOURCE_MAPPING_PATH = "JWT_RESOURCE_MAPPING_PATH";
   public static final String CUSTOM_REQUEST_HEADERS    = "CUSTOM_REQUEST_HEADERS";
   public static final String CUSTOM_RESPONSE_HEADERS   = "CUSTOM_RESPONSE_HEADERS";

   // ##################################################################################################################################
   // Sottoclassi 
   // ##################################################################################################################################
                                                                            
   // ==================================================================================================================================
   // Tipologie di token supportate per l'autenticazione JWT inbound
   // ==================================================================================================================================
   protected static class TokenTypes {
      public final static String JWT_AUTH_ID = "JWT";
      public final static String BASIC_AUTH_ID = "BASIC";

      public final static String TOKEN_PREFIX = "CIA.";
      
      public final static String BASIC_TYPE = TOKEN_PREFIX+BASIC_AUTH_ID;
      public final static String JWT_TYPE = TOKEN_PREFIX+JWT_AUTH_ID;
      public final static String JWT_TYPE1 = TOKEN_PREFIX+JWT_AUTH_ID+"#1";
      public final static String JWT_TYPE2 = TOKEN_PREFIX+JWT_AUTH_ID+"#2";
      public final static String ALL_TYPE = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID;      
      public final static String ALL_TYPE1 = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID+"#1";
      public final static String ALL_TYPE2 = TOKEN_PREFIX+JWT_AUTH_ID+"+"+BASIC_AUTH_ID+"#2";
      
      public final static List<String> ALL_TYPES = 
         Arrays.asList(CustomInboundAuthenticator.TokenTypes.BASIC_TYPE, 
                       CustomInboundAuthenticator.TokenTypes.JWT_TYPE,CustomInboundAuthenticator.TokenTypes.ALL_TYPE, 
                       CustomInboundAuthenticator.TokenTypes.JWT_TYPE1,CustomInboundAuthenticator.TokenTypes.ALL_TYPE1, 
                       CustomInboundAuthenticator.TokenTypes.JWT_TYPE2,CustomInboundAuthenticator.TokenTypes.ALL_TYPE2);
   }
   
   // ##################################################################################################################################
   // Variabili
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Variabili globali statiche di classe
   // ==================================================================================================================================

   // Contatore istanze del provider
   protected static byte IntInstanceCount = 0;
   
   // Registro delle istanze del provider di inbound
   protected static ProviderRegistry ObjInboundRegistry = new ProviderRegistry();
      
   // ##################################################################################################################################
   // Costruttore
   // ##################################################################################################################################

   public CustomInboundAuthenticator() {
      super();      
      StrInstanceID = "CIA:"+String.format("%03X",IntInstanceCount++);      
   }
   
   // ##################################################################################################################################
   // Implementa interfacce per security provider
   // ##################################################################################################################################

   @Override
   public void initialize(ProviderMBean ObjMBean, SecurityServices ObjSecurityServices) {       
      
      // Richiama costruttore padre
      init(ObjMBean);
               
      // Salva l'istanza del provider di inbound nel registry    
      ObjInboundRegistry.put(ObjProviderContext.providerName,this);                 
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
      return this;
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
   // Implementa identity asserter
   // ##################################################################################################################################
   
   @Override
   public CallbackHandler assertIdentity(String StrTokenType,Object ObjToken,ContextHandler ObjRequestContext) throws IdentityAssertionException {
      
      // Inizializza nome del thread
      setThreadName();
         
      // Crea logger,config e context
      LogManager Logger = createLogger();
      RuntimeConfig Config = createConfig();      
      RuntimeContext Context = createContext(ObjRequestContext);            
      
      // Esegue in modo sincrono o asincrono in base a configurazione
      CallbackHandler ObjCallback;
      if (Config.getString(THREADING_MODE).equals("SERIAL")) {
         ObjCallback = assertIdentitySynchImpl(StrTokenType,ObjToken);
      } else {      
         ObjCallback = assertIdentityAsynchImpl(StrTokenType,ObjToken);
      }
      
      // Ripulisce esplicitamente le variabili di thread
      cleanThread();      
      
      // Restituisce callback
      return ObjCallback;
   }

   // ==================================================================================================================================
   // Implementazione sincrona (serializza le richieste consentendo solo un thread alla volta)
   // ==================================================================================================================================
   private synchronized CallbackHandler assertIdentitySynchImpl(String StrTokenType, Object ObjToken) throws IdentityAssertionException {    
      return assertIdentityAsynchImpl(StrTokenType,ObjToken);
   }                                     

   // ==================================================================================================================================
   // Implementazione asincrona (consente esecuzione parallela le richieste)
   // ==================================================================================================================================
   private CallbackHandler assertIdentityAsynchImpl(String StrTokenType, Object ObjToken) throws IdentityAssertionException {  
      
      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();

      // Imposta livello di padding
      Logger.setPadLength(31);
      
      // ==================================================================================================================================
      // Gestisce asserzione di debug
      // ==================================================================================================================================   
      manageDebuggingAssertion();

      // ==================================================================================================================================
      // Logging configurazione
      // ==================================================================================================================================
      if (Logger.checkLogLevel(LogLevel.DEBUG)) {
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"INBOUND AUTH");
         Logger.logMessage(LogLevel.DEBUG,"##########################################################################################");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CONFIGURATION");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logProperty(LogLevel.DEBUG,"PROVIDER_TYPE",Config.getString(PROVIDER_TYPE));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_LINES",Config.getString(LOGGING_LINES));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_LEVEL",Config.getString(LOGGING_LEVEL));
         Logger.logProperty(LogLevel.DEBUG,"LOGGING_INFO",Config.getString(LOGGING_INFO));
         Logger.logProperty(LogLevel.DEBUG,"THREADING_MODE",Config.getString(THREADING_MODE));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_PROXY_MODE",Config.getString(REQUESTS_PROXY_MODE));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_PROXY_PATH",Config.getString(REQUESTS_PROXY_PATH));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_SSL_VERIFY",Config.getString(REQUESTS_SSL_VERIFY));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_CONN_TIMEOUT",Config.getString(REQUESTS_CONN_TIMEOUT));
         Logger.logProperty(LogLevel.DEBUG,"REQUESTS_READ_TIMEOUT",Config.getString(REQUESTS_READ_TIMEOUT));
         Logger.logProperty(LogLevel.DEBUG,"BASIC_AUTH",Config.getString(BASIC_AUTH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_AUTH",Config.getString(JWT_AUTH));
         Logger.logProperty(LogLevel.DEBUG,"JWT_POLICIES_PATH",Config.getString(JWT_POLICIES_PATH));      
         Logger.logProperty(LogLevel.DEBUG,"JWT_RESOURCE_MAPPING_PATH",Config.getString(JWT_RESOURCE_MAPPING_PATH));      
         Logger.logProperty(LogLevel.DEBUG,"CUSTOM_REQUEST_HEADERS",StringUtils.join(Config.getProperties(CUSTOM_REQUEST_HEADERS),","));
         Logger.logProperty(LogLevel.DEBUG,"CUSTOM_RESPONSE_HEADERS",StringUtils.join(Config.getProperties(CUSTOM_RESPONSE_HEADERS),","));
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
         validateParameter(JWT_RESOURCE_MAPPING_PATH);
         
         if (!Config.getString(REQUESTS_PROXY_MODE).equals("DIRECT")) validateParameter(REQUESTS_PROXY_PATH);      
         
      } catch (Exception ObjException) {
         throw new IdentityAssertionException(ObjException.getMessage());
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
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logProperty(LogLevel.DEBUG,"Server Host",Context.getString("http.server.host"));               
         Logger.logProperty(LogLevel.DEBUG,"Server Addr",Context.getString("http.server.addr"));               
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logProperty(LogLevel.DEBUG,"Client Host",Context.getString("http.client.host"));        
         Logger.logProperty(LogLevel.DEBUG,"Client Addr",Context.getString("http.client.addr")); 
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logProperty(LogLevel.DEBUG,"Request URL",Context.getString("http.request.url"));        
         Logger.logProperty(LogLevel.DEBUG,"Content Type",Context.getString("http.content.type"));        
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      }

      // ==================================================================================================================================
      // Gestisce l'asserzione di identità
      // ==================================================================================================================================      
      String StrToken = "";
      String StrAuthType = "";
      
      try {
         
         // Verifica la tipologia del token
         if (!(ObjToken instanceof String)) {
            String StrError = "Unsupported token class";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjToken.getClass().getSimpleName());
            throw new Exception(StrError);
         }

         // Verifica la correttezza del tipo di token
         if (!TokenTypes.ALL_TYPES.contains(StrTokenType)) {        
            String StrError = "Unknown token type";
            Logger.logMessage(LogLevel.ERROR,StrError,StrTokenType);
            throw new Exception(StrError);
         }   
         
         // Se necessario genera logging di debug
         Logger.logProperty(LogLevel.DEBUG,"Selected Token",StrTokenType);
         
         // Verifica se il token in ingresso è un BASIC o un JWT
         StrToken = (String)ObjToken;
         
         if (StrToken.startsWith("Basic ")) {
            StrAuthType = TokenTypes.BASIC_AUTH_ID;
            StrToken = StrToken.substring("Basic ".length());         
         } else {
            StrAuthType = TokenTypes.JWT_AUTH_ID;
            if (StrToken.startsWith("Bearer ")) {
               StrToken = StrToken.substring("Bearer ".length());
            }
         }

         // Aggiorna context
         Context.put("authtype",StrAuthType);
         
         // Genera logging      
         Logger.logProperty(LogLevel.DEBUG,"Detected Auth",StrAuthType);
               
         // Verifica la ammissibilità dell'autenticazione rilevata rispetto al token selezionato e ai flag di disattivazione
         if ((!StrTokenType.contains(StrAuthType))||
             (StrAuthType.equals(TokenTypes.JWT_AUTH_ID)&&Config.getString(JWT_AUTH).equals("DISABLE"))||
             (StrAuthType.equals(TokenTypes.BASIC_AUTH_ID)&&Config.getString(BASIC_AUTH).equals("DISABLE"))) {
            throw new Exception("Disabled auth type");
         }
         
      } catch (Exception ObjException) {
         String StrError = "Token preparation error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);         
      }
      
      // ==================================================================================================================================
      // Gestisce l'autenticazione
      // ==================================================================================================================================      
      switch (StrAuthType) {
       
         case TokenTypes.JWT_AUTH_ID: manageJwtAuthInbound(StrToken); break;
         case TokenTypes.BASIC_AUTH_ID: manageBasicAuthInbound(StrToken); break;
      }     
      
      // ==================================================================================================================================
      // Gestisce custom headers
      // ==================================================================================================================================
      Properties ObjRequestHeaders = Config.getProperties(CUSTOM_REQUEST_HEADERS);                                                 
      Properties ObjResponseHeaders = Config.getProperties(CUSTOM_RESPONSE_HEADERS);                                                 
      if ((ObjRequestHeaders!=null)||(ObjResponseHeaders!=null)) manageCustomHeaders(ObjRequestHeaders,ObjResponseHeaders);
      
      // ==================================================================================================================================
      // Gestisce debugging properties
      // ==================================================================================================================================
      manageDebuggingProperties();
      
      // ==================================================================================================================================
      // Gestisce logging informativo
      // ==================================================================================================================================
      try {
         // Genera logging di sintesi della asserzione
         Logger.logMessage(LogLevel.INFO,"Inbound ("+StrAuthType+") => "+StringUtils.replaceTemplates(Context,Config.getString(LOGGING_INFO)));
      } catch (Exception ObjException) {
         String StrError = "Logging info error";
         Logger.logMessage(LogLevel.WARN,StrError,ObjException);
      }         

      // ==================================================================================================================================
      
      // Restituisce utente autenticato
      return new CustomInboundAuthenticatorCallbackHandler(Context.getString("username"));
   }

   // ##################################################################################################################################
   // Metodi privati di supporto
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Gestisce autenticazione BASIC
   // ==================================================================================================================================      
   protected void manageBasicAuthInbound(String StrToken) throws IdentityAssertionException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
         
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"BASIC AUTH");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");  
                        
      try {          
         
         // Decodifica il token basic
         String[] ArrCredential = SecurityUtils.decodeBase64(StrToken).split(":",2);   

         // Salva identità del token base64                  
         Context.put("identity",ArrCredential[0]);
         Logger.logProperty(LogLevel.DEBUG,"Basic Identity",Context.getString("identity"));

         // Prova ad autenticare le credenziali sul realm weblogic
         Context.put("username",ObjProviderContext.wlsAuthenticator.authenticate(ArrCredential[0], ArrCredential[1]));
         
         // Se l'utenza non à autenticata genera eccezione
         if (Context.getString("username").equals("")) {
            throw new Exception("wrong credentials");
         }
               
      } catch (Exception ObjException) {
         String StrError = "Basic auth error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);        
      }  
      
      // Genera logging
      Logger.logProperty(LogLevel.DEBUG,"Realm UserName",Context.getString("username"));      
   }

   // ==================================================================================================================================
   // Gestisce autenticazione JWT inbound basata sulle policy
   // ==================================================================================================================================
   protected void manageJwtAuthInbound(String StrToken) throws IdentityAssertionException {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      Logger.logMessage(LogLevel.DEBUG,"JWT AUTH");
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Crea nuova istanza del token e acquisisce id della chiave di firma e issuer (non ancora verificati)
      // ----------------------------------------------------------------------------------------------------------------------------------
      JWTProvider ObjToken;

      try {
         ObjToken = prepareToken(StrToken);
      } catch (Exception ObjException) {
         throw new IdentityAssertionException(ObjException.getMessage());
      }

      // Aggiorna il riferimento al token nel context
      Context.put("token", ObjToken);

      // Acquisisce id della chiave di firma e issuer
      String StrKeyID = ObjToken.getKeyID();
      Object ObjIssuer = ObjToken.getPayload().get("iss");
      String StrIssuer = (ObjIssuer!=null)?(ObjIssuer.toString().trim()):("");
      
      // Se l'issuer non e' presente nel token genera eccezione
      if (StrIssuer.isEmpty()) {
         String StrError = "Token issuer error";
         Logger.logMessage(LogLevel.ERROR,StrError,"missing issuer");
         throw new IdentityAssertionException(StrError);
      }

      // Genera logging
      Logger.logProperty(LogLevel.DEBUG,"Token Issuer",StrIssuer);

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Acquisisce le policy e determina provider e claim dell'identita' in base all'issuer
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrPROVIDER = "";
      XmlObject ObjPolicies = null;
      XmlObject ObjIssuerPolicies = null;
      XmlObject ObjProviderPolicies = null;

      try {

         // Se presenti rimpiazza i template nel path delle policy
         String StrPoliciesParsedPath = StringUtils.replaceTemplates(Context,Config.getString(JWT_POLICIES_PATH));
         Logger.logProperty(LogLevel.DEBUG,"Policies Path",StrPoliciesParsedPath);

         // Valida e acquisisce il file delle policy di sicurezza
         ObjPolicies = validateResource(StrPoliciesParsedPath);

         // Cerca l'issuer confrontando gli url in java (il valore proviene dal token e non va inserito in un xpath)
         for (XmlObject ObjItem : ObjPolicies.selectPath("/inboundPolicies/issuers/item")) {
            if (StrIssuer.equals(XMLUtils.getAttributeValue(ObjItem,"issuerURL",null))) {
               ObjIssuerPolicies = ObjItem;
               break;
            }
         }

         // Se l'issuer non e' censito nelle policy genera eccezione
         if (ObjIssuerPolicies==null) throw new Exception("unknown issuer");

         // Acquisisce il provider dell'issuer e le relative policy
         StrPROVIDER = XMLUtils.getAttributeValue(ObjIssuerPolicies,"provider",null);
         ObjProviderPolicies = ObjPolicies.selectPath("/inboundPolicies/providers/item[@name='"+StrPROVIDER+"']")[0];

         // Aggiorna context
         Context.put("provider",StrPROVIDER);
         Context.put("jwks_url",XMLUtils.getAttributeValue(ObjProviderPolicies,"jwksURL",null));
         Context.put("identity_claim",XMLUtils.getAttributeValue(ObjIssuerPolicies,"identity_claim",null));
         Context.put("keys_cache_ttl",XMLUtils.getAttributeValue(ObjProviderPolicies,"keys_cache_ttl",null));

      } catch (Exception ObjException) {
         String StrError = "Issuer policies error ("+StrIssuer+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
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
         String StrError = "Resource mappings error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // Logging policies
      if (Logger.checkLogLevel(LogLevel.TRACE)) {
         Logger.logProperty(LogLevel.TRACE,"Issuer Policies",linearizeXml(ObjIssuerPolicies));
         Logger.logProperty(LogLevel.TRACE,"Provider Policies",linearizeXml(ObjProviderPolicies));
      }

      // Genera logging
      Logger.logProperty(LogLevel.DEBUG,"Provider",StrPROVIDER);
      Logger.logProperty(LogLevel.DEBUG,"Identity Claim",Context.getString("identity_claim"));

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara chiave per la verifica della firma
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrKeyModulus = "";
      String StrKeyExponent = "";
      try {

         // Prepara la chiave
         JWTKeysCacheEntry ObjKey = prepareKey(StrKeyID);

         // Acuisisce parametri chiave dalla cache
         StrKeyModulus = ObjKey.modulus;
         StrKeyExponent = ObjKey.exponent;

      } catch (Exception ObjException) {
         String StrError = "Keys retrieving error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Verifica la firma del token jwt
      // ----------------------------------------------------------------------------------------------------------------------------------

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"TOKEN VALIDATION");
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logProperty(LogLevel.DEBUG,"Key ID",StrKeyID);
      Logger.logProperty(LogLevel.TRACE,"Key Modulus",StrKeyModulus);
      Logger.logProperty(LogLevel.TRACE,"Key Exponent",StrKeyExponent);

      try {

         // Ammette solo l'algoritmo atteso (l'algoritmo di verifica non deve essere scelto dal token)
         Object ObjAlgorithm = ObjToken.getHeader().get("alg");
         if (!"RS256".equals(ObjAlgorithm)) throw new Exception("unsupported algorithm ("+ObjAlgorithm+")");

         // Verifica firma e scadenza del token jwt
         if (!ObjToken.verify(StrKeyModulus, StrKeyExponent)) throw new Exception("invalid signature");

         // Genera logging
         Logger.logProperty(LogLevel.DEBUG,"Validation","true");

      } catch (Exception ObjException) {
         String StrError = "Token validation error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Gestisce asserzione dell'identita'
      // ----------------------------------------------------------------------------------------------------------------------------------

      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.DEBUG,"IDENTITY ASSERTION");
      Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");

      String StrClientID = "";
      String StrProfile = null;

      try {

         // Acquisisce il valore del claim dell'identita' (anche se non di tipo stringa)
         Object ObjClaim = ObjToken.getPayload().get(Context.getString("identity_claim"));
         if (ObjClaim==null) throw new Exception("missing claim '"+Context.getString("identity_claim")+"'");

         // Aggiorna context
         StrClientID = ObjClaim.toString();
         Context.put("client_id",StrClientID);

         // Traduce il client_id nell'identita' mediante il mapping delle risorse e aggiorna context
         Context.put("identity",reverseTranslateResource((XmlObject)Context.get("resource_mappings"),StrPROVIDER,StrClientID));

      } catch (Exception ObjException) {
         String StrError = "Identity mapping error ("+StrPROVIDER+":"+StrClientID+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      try {

         // Cerca l'identita' tra quelle abilitate per il provider nelle policy (il nome proviene dal mapping delle risorse)
         XmlObject[] ArrIdentityPolicies = 
            ObjPolicies.selectPath(
               "/inboundPolicies/identities/provider[@name='"+StrPROVIDER+"']/item[@identity='"+Context.getString("identity")+"']");

         // Se l'identita' non e' abilitata nelle policy genera eccezione
         if (ArrIdentityPolicies.length!=1) throw new Exception("identity not enabled");

         // Acquisisce utenza del realm ed eventuale profilo e aggiorna context
         StrProfile = XMLUtils.getAttributeValue(ArrIdentityPolicies[0],"profile",null);
         Context.put("username",XMLUtils.getAttributeValue(ArrIdentityPolicies[0],"username",null));
         Context.put("profile",StrProfile);

      } catch (Exception ObjException) {
         String StrError = "Identity policies error ("+Context.getString("identity")+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // Genera logging
      Logger.logProperty(LogLevel.DEBUG,"Client ID",StrClientID);
      Logger.logProperty(LogLevel.DEBUG,"Identity",Context.getString("identity"));
      Logger.logProperty(LogLevel.DEBUG,"Profile",Context.getString("profile"));

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Verifica l'audience del token (quella del profilo prevale su quella del provider)
      // ----------------------------------------------------------------------------------------------------------------------------------
      String StrAudience = "";

      try {

         // Determina l'audience attesa
         if (StrProfile!=null) {
            StrAudience = XMLUtils.getAttributeValue(ObjPolicies.selectPath("/inboundPolicies/profiles/item[@name='"+StrProfile+"']")[0],"audience",null);
         } else {
            StrAudience = XMLUtils.getAttributeValue(ObjProviderPolicies,"audience",null);
         }

         // Aggiorna context
         Context.put("audience",StrAudience);

         // Traduce l'audience mediante il mapping delle risorse
         String StrMappedAudience = translateResource((XmlObject)Context.get("resource_mappings"),StrPROVIDER,StrAudience);
         Logger.logProperty(LogLevel.DEBUG,"Audience",StrAudience+" => "+StrMappedAudience);

         // Verifica che il token sia destinato all'audience attesa (il claim puo' essere una stringa o un array)
         Object ObjAudience = ObjToken.getPayload().get("aud");

         boolean BolAudience =
            (ObjAudience instanceof java.util.Collection)?
               (((java.util.Collection) ObjAudience).contains(StrMappedAudience)):
               (StrMappedAudience.equals(String.valueOf(ObjAudience)));

         if (!BolAudience) throw new Exception("audience mismatch ("+ObjAudience+")");

      } catch (Exception ObjException) {
         String StrError = "Audience error ("+StrAudience+")";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new IdentityAssertionException(StrError);
      }

      // Genera logging
      Logger.logProperty(LogLevel.DEBUG,"Realm UserName",Context.getString("username"));
   }

   // ==================================================================================================================================
   // Gestisce preparazione chiave di firma jwt dal jwks del provider
   // ==================================================================================================================================
   protected JWTKeysCacheEntry prepareKey(String StrKeyID) throws Exception {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();

      // Acquisisce url del jwks e durata della cache (determinati dalle policy del provider)
      String StrJwksURL = Context.getString("jwks_url");
      int IntKeysCacheTTL = Integer.parseInt(Context.getString("keys_cache_ttl"));

      // Verifica se la chiave e' gia' in cache e non e' scaduta (l'indice comprende l'url del jwks per distinguere i provider)
      JWTKeysCacheEntry ObjCachedKey = ObjProviderContext.jwtCache.validKey(StrJwksURL+"#"+StrKeyID,IntKeysCacheTTL);

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Se la chiave non e' in cache acquisisce il jwks
      // ----------------------------------------------------------------------------------------------------------------------------------
      if (ObjCachedKey==null) {

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logMessage(LogLevel.DEBUG,"KEYS RETRIEVE");
         Logger.logMessage(LogLevel.DEBUG,"------------------------------------------------------------------------------------------");
         Logger.logProperty(LogLevel.DEBUG,"Keys URL",StrJwksURL);

         // Acquisisce il jwks in formato stringa (l'host delle chiavi pubbliche e' sempre anonimo)
         String StrJwtKeys = fetchResource(HttpMethod.GET,
                                           StrJwksURL,null,"","application/json",
                                           "ANONYMOUS","","",
                                           Logger);

         // Acquisisce payload in formato json e genera logging
         JSONObject ObjJSON = new JSONObject(StrJwtKeys);
         Logger.logProperty(LogLevel.TRACE,"Payload (JSON)",ObjJSON.toString());

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Gestisce parsing e caching della chiave
         // ----------------------------------------------------------------------------------------------------------------------------------
         
         // Cerca nel jwks la chiave con il kid richiesto
         org.json.JSONArray ArrKeys = ObjJSON.getJSONArray("keys");
         JSONObject ObjKey = null;
         
         for (int IntIndex=0;IntIndex<ArrKeys.length();IntIndex++) {
            if (ArrKeys.getJSONObject(IntIndex).optString("kid").equals(StrKeyID)) {
               ObjKey = ArrKeys.getJSONObject(IntIndex);
               break;
            }
         }
         
         // Se la chiave non e' presente o non e' una chiave RSA di firma genera eccezione
         if ((ObjKey==null)||(!ObjKey.optString("kty").equals("RSA"))||(!ObjKey.optString("use","sig").equals("sig"))) {
            throw new Exception("key not found ("+StrKeyID+")");
         }
         
         // Estrapola modulo ed esponente
         String StrKeyModulus = ObjKey.optString("n");
         String StrKeyExponent = ObjKey.optString("e");
         
         // Se modulo o esponente non sono valorizzati genera eccezione
         if (StrKeyModulus.equals("")||StrKeyExponent.equals("")) {
            throw new Exception("unable to extract key");
         } 
         
         // Salva la chiave in cache e la restituisce
         ObjCachedKey = ObjProviderContext.jwtCache.putKey(StrJwksURL+"#"+StrKeyID,StrKeyModulus,StrKeyExponent);
      }

      // Restituisce chiave
      return ObjCachedKey;
   }

   // ==================================================================================================================================
   // Crea nuova configurazione di thread in modalità inbound
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
                           
      Config.put(BASIC_AUTH,getProviderMBean().getBASIC_AUTH());
      Config.put(JWT_AUTH,getProviderMBean().getJWT_AUTH());
      
      Config.put(JWT_POLICIES_PATH,getProviderMBean().getJWT_POLICIES_PATH());
      Config.put(JWT_RESOURCE_MAPPING_PATH,getProviderMBean().getJWT_RESOURCE_MAPPING_PATH());
      
      Config.put(CUSTOM_REQUEST_HEADERS,getProviderMBean().getCUSTOM_REQUEST_HEADERS());
      Config.put(CUSTOM_RESPONSE_HEADERS,getProviderMBean().getCUSTOM_RESPONSE_HEADERS());
               
      Config.put(DEBUGGING_ASSERTION,getProviderMBean().getDEBUGGING_ASSERTION());
      Config.put(DEBUGGING_PROPERTIES,getProviderMBean().getDEBUGGING_PROPERTIES());
               
      // Prepara livelli di logging di default 
      LogManager Logger = getLogger();
      Logger.setLogLines(Config.getInteger(LOGGING_LINES));
      Logger.setLogLevel(Config.getString(LOGGING_LEVEL));
      
      return Config;   
   } 

   // ==================================================================================================================================
   // Crea nuovo context di thread in modalità inbound
   // ==================================================================================================================================    
   protected RuntimeContext createContext(ContextHandler ObjRequestContext) {   
         
      // Estrapola il contesto di request
      ServiceInfo ObjService = (ServiceInfo) ObjRequestContext.getValue("com.bea.contextelement.alsb.service-info");
      TransportEndPoint ObjEndpoint = (TransportEndPoint) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.endpoint"); 
      HttpServletRequest ObjRequest = (HttpServletRequest) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-request");
      HttpServletResponse ObjResponse = (HttpServletResponse) ObjRequestContext.getValue("com.bea.contextelement.alsb.transport.http.http-response");

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto comuni
      // ----------------------------------------------------------------------------------------------------------------------------------
      RuntimeContext Context = super.createContext("inbound",ObjService);
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto statiche (ad uso interno, non utilizzabili come template)
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("http.request",ObjRequest);    
      Context.put("http.response",ObjResponse);
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto statiche (usabili come template)
      // ----------------------------------------------------------------------------------------------------------------------------------   
      Context.put("http.request.url",ObjRequest.getRequestURL().toString());      
      Context.put("http.request.proto",ObjRequest.getProtocol());      
      Context.put("http.request.scheme",ObjRequest.getScheme());  
      
      Context.put("http.client.host",ObjRequest.getRemoteHost());      
      Context.put("http.client.addr",ObjRequest.getRemoteAddr());  
      
      Context.put("http.server.host",ObjRequest.getLocalName());      
      Context.put("http.server.addr",ObjRequest.getLocalAddr());      
      Context.put("http.server.name",ObjRequest.getServerName());      
      Context.put("http.server.port",String.valueOf(ObjRequest.getServerPort()));
      
      Context.put("http.content.type",ObjRequest.getContentType());      
      Context.put("http.content.length",String.valueOf(ObjRequest.getContentLength()));    
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche semplici
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("http.content.body",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return StringUtils.toString(ObjRequest.getInputStream());
         }
      });             
      Context.put("http.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return Logger.formatProperties(LogLevel.DEBUG,HttpUtils.getHeaders(ObjRequest, Arrays.asList("Authorization")),StringUtils.repeat(90,"-"),false);
         }
      });        
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche regex
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.putRegex("^http\\.header\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            HttpServletRequest ObjRequest = (HttpServletRequest) ObjContext.get("http.request");
            return StringUtils.join(ObjRequest.getHeaders(StrVariableName.split("\\.")[2]),"|") ; 
         }
      });
      // ----------------------------------------------------------------------------------------------------------------------------------

      return Context;   
   }    

   // ==================================================================================================================================
   // Acquisisce provider
   // ==================================================================================================================================    
   protected CustomInboundAuthenticatorMBean getProviderMBean() {
      return (CustomInboundAuthenticatorMBean) ObjProviderContext.providerMBean;
   }
}
