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


import com.bea.wli.sb.resources.schema.SchemaRepository;

import java.util.UUID;
import java.util.Map;
import java.util.Date;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.LinkedHashMap;
import java.util.jar.JarFile;
import java.util.jar.Attributes;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.File;

import javax.script.ScriptEngine;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import weblogic.management.security.ProviderMBean;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.ProviderInitializationException;

import com.bea.wli.sb.services.ServiceInfo;

import com.bea.xbean.xb.xsdschema.SchemaDocument;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlError;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;

import org.falpi.*;
import org.falpi.utils.*;
import org.falpi.utils.WLSUtils.*;
import org.falpi.utils.HttpUtils.*;
import org.falpi.utils.StringUtils.*;
import org.falpi.utils.jwt.JWTCache;
import org.falpi.utils.jwt.JWTProvider;
import org.falpi.utils.logging.*;

// ##################################################################################################################################
// Classe principale
// ##################################################################################################################################

public abstract class CustomAuthenticator {
   
   // ##################################################################################################################################
   // Costanti 
   // ##################################################################################################################################
   
   // Identificativi dei parametri di configurazione
   public static final String PROVIDER_TYPE          = "PROVIDER_TYPE";
   public static final String LOGGING_LINES          = "LOGGING_LINES";
   public static final String LOGGING_LEVEL          = "LOGGING_LEVEL";
   public static final String LOGGING_INFO           = "LOGGING_INFO";
   public static final String THREADING_MODE         = "THREADING_MODE";
   public static final String REQUESTS_PROXY_MODE    = "REQUESTS_PROXY_MODE";
   public static final String REQUESTS_PROXY_PATH    = "REQUESTS_PROXY_PATH";
   public static final String REQUESTS_SSL_VERIFY    = "REQUESTS_SSL_VERIFY";
   public static final String REQUESTS_CONN_TIMEOUT  = "REQUESTS_CONN_TIMEOUT";
   public static final String REQUESTS_READ_TIMEOUT  = "REQUESTS_READ_TIMEOUT";
   public static final String DEBUGGING_ASSERTION    = "DEBUGGING_ASSERTION";
   public static final String DEBUGGING_PROPERTIES   = "DEBUGGING_PROPERTIES";
   public static final String KERBEROS_CONFIGURATION = "KERBEROS_CONFIGURATION";

   // Timeout di default (secondi) usato al posto di valori non positivi, che per HttpClient significano attesa infinita
   public static final int DEFAULT_REQUESTS_TIMEOUT  = 5;

   // ##################################################################################################################################
   // Sottoclassi 
   // ##################################################################################################################################
   
   // ==================================================================================================================================
   // Gestore dei custom header
   // ==================================================================================================================================
   protected static class CustomHeader {
      protected String value;
      protected Boolean secure;
      
      CustomHeader(String StrHeaderValue,Boolean BolSecure) {
         value = StrHeaderValue;
         secure = BolSecure;
      }
   } 
   protected static class CustomHeaders extends LinkedHashMap<String,CustomHeader> {}

   // ==================================================================================================================================
   // Gestore della configurazione e contesti di runtime
   // ==================================================================================================================================
   protected static class RuntimeConfig extends SuperMap {}
   protected static class RuntimeContext extends SuperMap {}
   protected static class ProviderRegistry extends HashMap<String,CustomAuthenticator> {}
   protected static class ProviderDescriptor extends LinkedHashMap<String,PropertyDescriptor> {}
   
   // ==================================================================================================================================
   // Incapsula le proprietà di contesto del provider
   // ==================================================================================================================================
   protected static class ProviderContext {
              
      // Parametri weblogic
      protected String realmName;
      protected String domainName;
      protected String managedName;

      // Proprietà del provider
      protected String providerType;  
      protected String providerName;
      protected String providerTitle;  
      protected String packageTitle;  
      protected ProviderMBean providerMBean;
      protected ProviderDescriptor providerDescriptor;
      
      // Classi varie di servizio
      protected JWTCache jwtCache;
      protected JWTProvider jwtProvider;
      protected ScriptEngine scriptEngine;   
      protected Authenticator wlsAuthenticator;
   } 
   
   // ##################################################################################################################################
   // Variabili
   // ##################################################################################################################################

   // ==================================================================================================================================
   // Variabili globali statiche di classe
   // ==================================================================================================================================

   // Cache degli esiti di validazione delle risorse (path risorsa => timestamp risorsa|path schema|timestamp schema)
   protected static ConcurrentHashMap<String,String> ObjValidationCache = new ConcurrentHashMap<String,String>();
      
   // ==================================================================================================================================
   // Variabili globali statiche di thread
   // ==================================================================================================================================

   // Logger, config e context di thread
   protected static final ThreadLocal<LogManager> ObjThreadLogger = new ThreadLocal<LogManager>();
   protected static final ThreadLocal<RuntimeConfig> ObjThreadConfig = new ThreadLocal<RuntimeConfig>();
   protected static final ThreadLocal<RuntimeContext> ObjThreadContext = new ThreadLocal<RuntimeContext>();
      
   // ==================================================================================================================================
   // Variabili locali di istanza
   // ==================================================================================================================================
         
   // Contatore esecuzioni thread (di fatto è il numero di request gestite per istanza)
   protected long IntThreadCount;

   // Identificativo unico dell'itanza
   protected String StrInstanceID;
     
   // Proprietà di contesto dell'istanza
   protected ProviderContext ObjProviderContext;
   
   // ##################################################################################################################################
   // Costruttore
   // ##################################################################################################################################
          
   public CustomAuthenticator() {
      IntThreadCount = 0;
   }
          
   // ##################################################################################################################################
   // Metodi
   // ##################################################################################################################################
      
   public void init(ProviderMBean ObjMBean) {
            
      // Inizializza nome del thread
      setThreadName();
         
      // Prepara logger
      LogManager Logger = createLogger();

      // ==================================================================================================================================
      // Genera logging      
      // ==================================================================================================================================
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");
      Logger.logMessage(LogLevel.INFO,"INITIALIZE");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");     
      
      // ==================================================================================================================================
      // Inizializza contesto provider
      // ==================================================================================================================================
      ObjProviderContext = new ProviderContext();  
      ObjProviderContext.providerName = ObjMBean.getName();
      ObjProviderContext.providerTitle = ObjMBean.getDescription()+" ("+ObjMBean.getVersion()+")";
      ObjProviderContext.providerMBean = ObjMBean;
      ObjProviderContext.packageTitle = getPackageTitle();

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Acquisisce identificativo univoco del provider
      // ----------------------------------------------------------------------------------------------------------------------------------
      try {                  
         ObjProviderContext.providerType = (String) getProviderMBeanAttribute(PROVIDER_TYPE);
      } catch (Exception ObjException) {
         String StrError = "Provider config error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      }

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Costruisce il descrittore dell'mbeaninfo
      // ----------------------------------------------------------------------------------------------------------------------------------
      try {                  
                         
         // Carica la classe auto-generata MBeanInfo
         BeanInfo ObjMBeanInfo = Introspector.getBeanInfo(ObjMBean.getClass());         
         
         // Estrapola dallo MBeanInfo il descrittore delle proprietà del provider
         PropertyDescriptor[] ArrProperties = ObjMBeanInfo.getPropertyDescriptors();
         
         ObjProviderContext.providerDescriptor = new ProviderDescriptor();
                  
         for (int IntIndex=0;IntIndex<ArrProperties.length;IntIndex++) {
            PropertyDescriptor ObjProperty = ArrProperties[IntIndex];
            ObjProviderContext.providerDescriptor.put(ObjProperty.getName(),ObjProperty);
         }         
                  
      } catch (Exception ObjException) {
         String StrError = "MBeanInfo load error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      }

      // ==================================================================================================================================
      // Prepara contesto weblogic
      // ==================================================================================================================================            
      try {        
         ObjProviderContext.realmName = ObjMBean.getRealm().getName();
         ObjProviderContext.domainName = WLSUtils.getDomainName();
         ObjProviderContext.managedName = WLSUtils.getManagedName();      
         ObjProviderContext.wlsAuthenticator = WLSUtils.getAuthenticator(ObjMBean,ObjProviderContext.realmName,ObjProviderContext.domainName);        
      } catch (Exception ObjException) {
         String StrError = "WebLogic context error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      }

      // ==================================================================================================================================
      // Inizializza script engine
      // ==================================================================================================================================            
      try {
         ObjProviderContext.scriptEngine = JavaUtils.getScriptEngine();
      } catch (Exception ObjException) {
         String StrError = "Script engine error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      }

      // ==================================================================================================================================
      // Inizializza cache e provider jwt 
      // ==================================================================================================================================      
      try {
         
         // Crea istanza per il caching di chiavi e token jwt
         ObjProviderContext.jwtCache = new JWTCache(); 
         
         // Seleziona l'implementazione jwt in base alla versione java del target (supportati solo weblogic 12.2.1 e 14.1.2)
         // Se il target è weblogic 12.2.1 (java<17) poichè integra nimbus di una versione incompatibile occorre integrare una versione shaded 
         // Se il target è weblogic 14.1.2 (java>=17) poichè integra nimbus di una versione compatibile la si può usare diretamente
         ObjProviderContext.jwtProvider =
            JWTProvider.create((JavaUtils.getJavaVersion()<17)?("NimbusShaded"):("Nimbus"));
         
      } catch (Exception ObjException) {
         String StrError = "Token provider error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      } 
      
      // ==================================================================================================================================
      // Inizializza autenticazione kerberos
      // ==================================================================================================================================
      try {
         String[] ArrKerberosConfig = (String[]) getProviderMBeanAttribute(KERBEROS_CONFIGURATION);
         String StrKerberosConfig = (ArrKerberosConfig==null)?(""):(StringUtils.join(ArrKerberosConfig,System.lineSeparator()));
         
         // Configura kerberos solo se la configurazione e' valorizzata, per non alterare le impostazioni kerberos della JVM
         if (!StrKerberosConfig.trim().isEmpty()) SecurityUtils.configKerberos(StrKerberosConfig);
         
      } catch (Exception ObjException) {
         String StrError = "Kerberos config error";
         Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
         throw new ProviderInitializationException(StrError+" ("+ObjProviderContext.providerName+")",ObjException);
      }

      // ==================================================================================================================================
      // Genera logging 
      // ==================================================================================================================================    
      Logger.logMessage(LogLevel.INFO,"Realm Name ............: " + ObjProviderContext.realmName);
      Logger.logMessage(LogLevel.INFO,"Domain Name ...........: " + ObjProviderContext.domainName);
      Logger.logMessage(LogLevel.INFO,"Managed Name ..........: " + ObjProviderContext.managedName);  
      Logger.logMessage(LogLevel.INFO,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.INFO,"Instance ID ...........: " + StrInstanceID);  
      Logger.logMessage(LogLevel.INFO,"Provider Type .........: " + ObjProviderContext.providerType);  
      Logger.logMessage(LogLevel.INFO,"Provider Name .........: " + ObjProviderContext.providerName);  
      Logger.logMessage(LogLevel.INFO,"Provider Title ........: " + ObjProviderContext.providerTitle);  
      Logger.logMessage(LogLevel.INFO,"Package Title .........: " + ObjProviderContext.packageTitle);  
      Logger.logMessage(LogLevel.INFO,"------------------------------------------------------------------------------------------");
      Logger.logMessage(LogLevel.INFO,"JWT Provider ..........: " + ObjProviderContext.jwtProvider.getClass().getCanonicalName());  
      Logger.logMessage(LogLevel.INFO,"Kerberos Config .......: " + SecurityUtils.getKerberosConfigPath());
      Logger.logMessage(LogLevel.INFO,"Scripting Engine ......: " + ObjProviderContext.scriptEngine.getFactory().getEngineName()+" ("+ObjProviderContext.scriptEngine.getFactory().getEngineVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"Scripting Language ....: " + ObjProviderContext.scriptEngine.getFactory().getLanguageName()+" ("+ObjProviderContext.scriptEngine.getFactory().getLanguageVersion()+")");  
      Logger.logMessage(LogLevel.INFO,"------------------------------------------------------------------------------------------");
   }

   public void done() {
      
      // Inizializza nome del thread
      setThreadName();
         
      // Prepara logger
      LogManager Logger = createLogger();

      // ==================================================================================================================================
      // Genera logging      
      // ==================================================================================================================================
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
      Logger.logMessage(LogLevel.INFO,"SHUTDOWN");
      Logger.logMessage(LogLevel.INFO,"##########################################################################################");      
   }

   // ##################################################################################################################################
   // Metodi di supporto
   // ##################################################################################################################################
                  
   // ==================================================================================================================================
   // Legge dal manifest del jar che contiene i provider le informazioni sul package scritte dal build
   // ==================================================================================================================================
   protected static String getPackageTitle() {

      try {

         // Individua il jar da cui e' stata caricata la classe
         URL ObjLocation = CustomAuthenticator.class.getProtectionDomain().getCodeSource().getLocation();
         JarFile ObjJarFile = new JarFile(new File(ObjLocation.toURI()));

         try {

            // Acquisisce gli attributi principali del manifest
            Attributes ObjAttributes = ObjJarFile.getManifest().getMainAttributes();
            String StrTitle = ObjAttributes.getValue("Implementation-Title");
            String StrVersion = ObjAttributes.getValue("Implementation-Version");

            // Se il manifest non contiene le informazioni sul package restituisce un valore convenzionale
            if ((StrTitle==null)||(StrVersion==null)) return "unknown";

            // Compone il titolo con data e target di build e con le versioni dei singoli provider
            return StrTitle+" "+StrVersion+" ("+ObjAttributes.getValue("Build-Date")+", "+ObjAttributes.getValue("Build-Target")+
                   ", legacy "+ObjAttributes.getValue("Legacy-Version")+", inbound "+ObjAttributes.getValue("Inbound-Version")+", outbound "+ObjAttributes.getValue("Outbound-Version")+")";

         } finally {
            ObjJarFile.close();
         }

      } catch (Exception ObjException) {

         // In caso di errore (classe non caricata da un jar, manifest assente, ecc.) non blocca l'inizializzazione
         return "unknown";
      }
   }

   // ==================================================================================================================================
   // Crea un nuovo token vuoto e lo salva nel context
   // ==================================================================================================================================
   protected JWTProvider prepareToken() throws Exception {
      return prepareToken("");
   }
   
   protected JWTProvider prepareToken(String StrToken) throws Exception {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();

      // ----------------------------------------------------------------------------------------------------------------------------------
      // Inizializza nuova istanza di token
      // ----------------------------------------------------------------------------------------------------------------------------------
      JWTProvider ObjJwtToken = null;
      try {

         // Crea nuova istanza del token
         ObjJwtToken = ObjProviderContext.jwtProvider.createInstance();

      } catch (Exception ObjException) {
         String StrError = "Token provider error";
         Logger.logMessage(LogLevel.ERROR, StrError, ObjException);
         throw new Exception(StrError);
      }
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Se è fornito un token ne esegue il parsing
      // ----------------------------------------------------------------------------------------------------------------------------------
      if ((StrToken!=null)&&(!StrToken.isEmpty())) {
         try {            
            
            // Esegue il parsing del token
            ObjJwtToken.parse(StrToken);                     
            
         } catch (Exception ObjException) {
            String StrError = "Token parsing error";
            Logger.logMessage(LogLevel.ERROR,StrError,ObjException);
            throw new IdentityAssertionException(StrError);        
         }      
      }
         
      return ObjJwtToken;
   }
   
   // ==================================================================================================================================
   // Gestisce custom headers
   // ==================================================================================================================================      
   protected void manageCustomHeaders(Properties ObjRequestHeaders,Properties ObjResponseHeaders) {
      manageCustomHeaders(ObjRequestHeaders,ObjResponseHeaders,true);
   }
   
   protected void manageCustomHeaders(Properties ObjRequestHeaders,Properties ObjResponseHeaders,Boolean BolLoggingBanner) {

      // Prepara logger e context
      LogManager Logger = getLogger();
      RuntimeContext Context = getContext();
            
      // Se necessario genera logging
      if (BolLoggingBanner) {
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"CUSTOM HEADERS");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
      }   
      
      // Gestisce cutom request headers    
      if (ObjRequestHeaders!=null) {    
         
         // Prepara tipo generico per gestione aggiunta header di request
         Object ObjRequest = Context.get("http.request");
         Boolean BolOutbound = Context.getString("context").equals("outbound");
         
         for (String StrHeaderName : ObjRequestHeaders.stringPropertyNames()) {
            try {
               String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjRequestHeaders.getProperty(StrHeaderName));
               
               if (!StrHeaderValue.isEmpty()) {
                  Logger.logMessage(LogLevel.DEBUG,"Request: "+StrHeaderName+"="+StrHeaderValue);
                  
                  if (BolOutbound) {
                     ((HttpURLConnection) ObjRequest).setRequestProperty(StrHeaderName, StrHeaderValue);
                  } else {
                     WLSUtils.addRequestHeader((HttpServletRequest)ObjRequest,StrHeaderName,StrHeaderValue);
                  }
               }
            } catch (Exception ObjException) {
               String StrError = "Custom request header error '"+StrHeaderName+"'";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }
         }
      }
      
      // Gestisce cutom response headers    
      if (ObjResponseHeaders!=null) {    
         HttpServletResponse ObjResponse = (HttpServletResponse) Context.get("http.response");        
         for (String StrHeaderName : ObjResponseHeaders.stringPropertyNames()) {
            try {
               String StrHeaderValue = StringUtils.replaceTemplates(Context,ObjResponseHeaders.getProperty(StrHeaderName));
               
               if (!StrHeaderValue.isEmpty()) {
                  Logger.logMessage(LogLevel.DEBUG,"Response: "+StrHeaderName+"="+StrHeaderValue);
                  ObjResponse.addHeader(StrHeaderName,StrHeaderValue);
               }
            } catch (Exception ObjException) {
               String StrError = "Custom response header error '"+StrHeaderName+"'";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }  
         }
      }
   }
   
   // ==================================================================================================================================
   // Gestisce debugging properties
   // ==================================================================================================================================   
   protected void manageDebuggingProperties() {
   
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      RuntimeContext Context = getContext();
      
      // Scandisce proprietà di debugging
      String[] ArrDebuggingProperties  = Config.getStringArray(DEBUGGING_PROPERTIES);

      if (ArrDebuggingProperties.length>0) {

         // Genera logging
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         Logger.logMessage(LogLevel.DEBUG,"DEBUGGING PROPERTIES");
         Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");
         
         for (String StrProperty : ArrDebuggingProperties) {
            try {
               Logger.logMessage(LogLevel.DEBUG,StrProperty+" => "+StringUtils.replaceTemplates(Context,StrProperty));
            } catch (Exception ObjException) {
               String StrError = "Debug property error";
               Logger.logMessage(LogLevel.WARN,StrError,ObjException);
            }
         }
      }
      
      // Genera logging
      Logger.logMessage(LogLevel.DEBUG,"==========================================================================================");   
   }
   
   // ==================================================================================================================================
   // Gestisce debugging properties
   // ==================================================================================================================================   
   protected void manageDebuggingAssertion() {
   
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      
      // Acquisisce asserzione di debug
      String StrDebuggingAssertion = StringUtils.join(Config.getStringArray(DEBUGGING_ASSERTION),System.lineSeparator());

      // Se l'asserzione è definita esegue
      if (!StrDebuggingAssertion.equals("")) {
         try {
            if (!((Boolean) evaluateScript(StrDebuggingAssertion,"Boolean"))) {
               Logger.setLogLevel(LogLevel.INFO);
            }
         } catch (Exception ObjException) {
            String StrError = "Debugging assertion error";
            Logger.logMessage(LogLevel.WARN,StrError,ObjException);
         }
      }
   }
   // ==================================================================================================================================
   // Acquisisce la risorsa xml e le valida rispetto allo schema referenziato dall'elemento radice
   // ==================================================================================================================================

   // Per default le anomalie di validazione generano solo logging di WARN
   protected XmlObject validateResource(String StrResourcePath) throws Exception {
      return validateResource(StrResourcePath,false);
   }

   // Se BolException e' true le anomalie di validazione generano eccezione, altrimenti solo logging di WARN
   protected XmlObject validateResource(String StrResourcePath,Boolean BolException) throws Exception {

      // Prepara logger
      LogManager Logger = getLogger();

      // Acquisisce la risorsa (se non e' disponibile genera sempre eccezione)
      XmlObject ObjResource = OSBUtils.getResourceCached("XML",StrResourcePath);

      try {

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Estrae dalla radice il puntamento allo schema
         // ----------------------------------------------------------------------------------------------------------------------------------
         String StrXsiNamespace = "http://www.w3.org/2001/XMLSchema-instance";
         XmlObject ObjRoot = ObjResource.selectPath("/*")[0];
         String StrLocation = XMLUtils.getAttributeValue(ObjRoot,"noNamespaceSchemaLocation",StrXsiNamespace);

         if ((StrLocation==null)||(StrLocation.trim().isEmpty())) throw new Exception("schema location not declared");
         StrLocation = StrLocation.trim();

         // Le location con schema (http:, file:, ...) non sono risorse OSB
         if (StrLocation.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*")) throw new Exception("unsupported schema location ("+StrLocation+")");

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Risolve la location in un path OSB (assoluta se inizia per "/" altrimenti relativa al folder della risorsa)
         // ----------------------------------------------------------------------------------------------------------------------------------
         ArrayList<String> ArrParts = new ArrayList<String>();

         if (!StrLocation.startsWith("/")) {
            String[] ArrBase = StrResourcePath.split("/");
            for (int IntIndex=0;IntIndex<ArrBase.length-1;IntIndex++) ArrParts.add(ArrBase[IntIndex]);
         }

         for (String StrPart : StrLocation.split("/")) {
            if (StrPart.isEmpty()||StrPart.equals(".")) continue;
            if (!StrPart.equals("..")) {
               ArrParts.add(StrPart);
            } else {
               if (ArrParts.isEmpty()) throw new Exception("invalid schema location ("+StrLocation+")");
               ArrParts.remove(ArrParts.size()-1);
            }
         }

         // Le risorse OSB non hanno estensione
         String StrSchemaPath = StringUtils.join(ArrParts,"/").replaceFirst("(?i)[.]xsd$","");

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Se risorsa e schema non sono cambiati rispetto alla ultima validazione positiva restituisce subito la risorsa
         // ----------------------------------------------------------------------------------------------------------------------------------
         String StrFootprint =
            OSBUtils.getResourceMetadata("XML",StrResourcePath).getDigest().getLastChangeTime()+"|"+StrSchemaPath+"|"+
            OSBUtils.getResourceMetadata("XMLSchema",StrSchemaPath).getDigest().getLastChangeTime();

         if (StrFootprint.equals(ObjValidationCache.get(StrResourcePath))) return ObjResource;

         // ----------------------------------------------------------------------------------------------------------------------------------
         // Acquisisce il testo dello schema (incapsulato nella entry della risorsa) ed esegue la validazione
         // ----------------------------------------------------------------------------------------------------------------------------------
         String StrSchema = SchemaRepository.get().getEntry(OSBUtils.getResourceRef("XMLSchema",StrSchemaPath)).getSchemaEntry().getSchema();
         ArrayList<XmlError> ArrErrors = XMLUtils.validate(ObjResource,new SchemaDocument[] { SchemaDocument.Factory.parse(StrSchema) });

         // Se ci sono errori esegue
         if (!ArrErrors.isEmpty()) {

            // Se richiesto genera eccezione con il dettaglio dei primi errori
            if (BolException) {
               StringBuilder ObjMessage = new StringBuilder("schema validation failed ("+ArrErrors.size()+" errors)");
               for (int IntIndex=0;IntIndex<Math.min(ArrErrors.size(),3);IntIndex++) ObjMessage.append(" - ").append(ArrErrors.get(IntIndex).getMessage());
               throw new Exception(ObjMessage.toString());
            }

            // Altrimenti genera logging di WARN con il dettaglio di tutti gli errori e restituisce comunque la risorsa
            Logger.logMessage(LogLevel.ERROR,"Resource validation failed ("+StrResourcePath+"): "+ArrErrors.size()+" errors");
            for (XmlError ObjError : ArrErrors) {
               Logger.logMessage(LogLevel.ERROR,"Validation error"+((ObjError.getLine()>0)?(" at line "+ObjError.getLine()):(""))+": "+ObjError.getMessage());
            }
            return ObjResource;
         }

         // Memorizza esito positivo
         ObjValidationCache.put(StrResourcePath,StrFootprint);

      } catch (Exception ObjException) {

         // Se richiesto propaga l'eccezione, altrimenti genera logging di WARN e restituisce comunque la risorsa
         if (BolException) throw ObjException;
         Logger.logMessage(LogLevel.ERROR,"Resource validation error ("+StrResourcePath+")",ObjException);
      }

      // Restituisce la risorsa
      return ObjResource;
   }
   
   // ==================================================================================================================================
   // Traduce il nome logico di una risorsa nel valore mappato per il provider indicato
   // ==================================================================================================================================
   protected String translateResource(XmlObject ObjResourceMappings,String StrProvider,String StrResourceName) throws Exception {

      // Estrapola gli elementi di interesse per il provider e la risorsa indicati
      XmlObject[] ArrMappedResource = 
         ObjResourceMappings.selectPath(
            "/resourceMappings/provider[@name='"+StrProvider+"']/item[@name='"+StrResourceName+"']");

      // Verifica la congruenza delle informazioni estratte
      if (ArrMappedResource.length!=1) throw new Exception("invalid resource mapping ("+StrProvider+":"+StrResourceName+")");

      // Restituisce il valore mappato
      return XMLUtils.getAttributeValue(ArrMappedResource[0],"value",null);
   }
   
   // ==================================================================================================================================
   // Traduce un valore mappato nel nome logico della risorsa per il provider indicato (traduzione inversa)
   // ==================================================================================================================================
   protected String reverseTranslateResource(XmlObject ObjResourceMappings,String StrProvider,String StrResourceValue) throws Exception {

      // Prepara variabili di lavoro
      String StrResourceName = null;
      
      // Cerca il valore tra le risorse del provider confrontando i valori in java (il valore puo' provenire da un token)
      for (XmlObject ObjItem : ObjResourceMappings.selectPath("/resourceMappings/provider[@name='"+StrProvider+"']/item")) {
         if (StrResourceValue.equals(XMLUtils.getAttributeValue(ObjItem,"value",null))) {
            
            // Se il valore e' mappato su piu' risorse genera eccezione
            if (StrResourceName!=null) throw new Exception("ambiguous resource mapping ("+StrProvider+":"+StrResourceValue+")");
            StrResourceName = XMLUtils.getAttributeValue(ObjItem,"name",null);
         }
      }

      // Se il valore non e' mappato genera eccezione
      if (StrResourceName==null) throw new Exception("unmapped value ("+StrProvider+":"+StrResourceValue+")");

      // Restituisce il nome della risorsa
      return StrResourceName;
   }
   
   // ==================================================================================================================================
   // Verifica se un parametro obbligatorio e valorizzato
   // ==================================================================================================================================
   protected void validateParameter(String StrParameterName) throws Exception {
         
      // Prepara logger & context
      LogManager Logger = getLogger();
      RuntimeConfig Config = getConfig();
      
      // Acquisisce il parametro indicato dalla configurazione
      Object ObjParameterValue = Config.get(StrParameterName);
      
      // Prepara nome della classe del parametro
      String StrClassName = (ObjParameterValue==null)?("null"):(ObjParameterValue.getClass().getSimpleName());

      // Se si tratta di un parametro stringa esegue trim
      if (StrClassName.equals("String")) {
         ObjParameterValue = ((String)ObjParameterValue).trim();
      }
      
      // Se necessario genera trace
      Logger.logMessage(LogLevel.TRACE,"Checking Parameter "+StrParameterName+": "+
                                       ((ObjParameterValue==null)?("is null"):
                                        ("class '"+StrClassName+"' "+
                                         ((!StrClassName.equals("String"))?(""):
                                          (ObjParameterValue.equals("")?("is empty"):("")))))); 
      
      // Verifica se il parametro è null o blank
      if ((ObjParameterValue==null)||((StrClassName.equals("String"))&&((String)ObjParameterValue).equals(""))) {
         String StrError = "Configuration error";
         Logger.logMessage(LogLevel.ERROR,StrError,"mandatory parameter missing '"+StrParameterName+"'");
         throw new Exception(StrError);
      }
      
      // Reimposta il parametro di configurazione dopo l'eventuale correzione
      Config.put(StrParameterName,ObjParameterValue);
   }   
   
   // ==================================================================================================================================
   // Prepare http header
   // ==================================================================================================================================
   
   // Prepara header di tipo inlined-attribute
   protected void prepareHeader(Map<String,CustomHeader> ObjHeaders,XmlObject ObjElement,String StrAttributeName) throws Exception {
            
      String StrAttributeValue = XMLUtils.getAttributeValue(ObjElement,StrAttributeName,null);  
      
      if (StrAttributeValue!=null) {
         String[] ArrHeader = StrAttributeValue.split(":",2);
         String StrHeaderName = ArrHeader[0].trim();
         String StrHeaderValue = ArrHeader[1].trim();
         ObjHeaders.put(StrHeaderName,new CustomHeader(StrHeaderValue,StrAttributeName.startsWith("secure")));
      }
   }
   
   // Prepara header di tipo element
   protected void prepareHeader(Map<String,CustomHeader> ObjHeaders,XmlObject ObjElement,String StrAttributeName,String StrValueName) throws Exception {
      
      for (XmlObject ObjAttributeElement : ObjElement.selectPath("./"+StrAttributeName)) {
         String StrHeaderName = XMLUtils.getAttributeValue(ObjAttributeElement,"name",null);
         String StrHeaderValue = XMLUtils.getAttributeValue(ObjAttributeElement,StrValueName,null);         
         ObjHeaders.put(StrHeaderName,new CustomHeader(StrHeaderValue,StrAttributeName.startsWith("secure")));
      }
   }   
   
   // ==================================================================================================================================
   // Linearize XML
   // ==================================================================================================================================
   protected String linearizeXml(XmlObject ObjDocument) {
      
      if (ObjDocument==null) return "";
      
      XmlCursor ObjCursor = ObjDocument.newCursor();
      ObjCursor.selectPath("descendant-or-self::text()[normalize-space(.) = '']");
      while (ObjCursor.hasNextSelection()) {
          ObjCursor.toNextSelection();
          ObjCursor.removeXml();
      }
      ObjCursor.dispose();
   
      return ObjDocument.xmlText(new XmlOptions().setSaveOuter().setSaveAggressiveNamespaces());
   }      
      
   // ==================================================================================================================================
   // Evaluate script
   // ==================================================================================================================================
   protected Object evaluateScript(String StrScript, String... ArrClassNames) throws Exception {
      
      // Prepara context
      RuntimeContext Context = getContext();               
      
      // Esegue lo script fornito
      Object ObjResult = ObjProviderContext.scriptEngine.eval(StringUtils.replaceTemplates(Context,StrScript));
      String StrResultClassName = ObjResult.getClass().getSimpleName();
      
      // Se la tipologia di oggetto restituita non tra quelle attese genera eccezione
      if ((ArrClassNames.length>0)&&(!Arrays.asList(ArrClassNames).contains(StrResultClassName))) {
         throw new Exception("unexpected result class '"+StrResultClassName+"'");
      }

      // Restrituisce l'oggetto risultante
      return ObjResult;
   }

   // ==================================================================================================================================
   // Gestisce preparazione access token per jwt outbund
   // ==================================================================================================================================
   protected String fetchResource(HttpMethod ObjHttpMethod,
                                  String StrResourceURL,byte[] ObjRequestBody,
                                  String StrRequestContentType,String StrResponseContentType,
                                  String StrHostAuthMode,String StrHostUserName,String StrHostPassword,
                                  LogManager Logger) throws Exception {

      // Prepara logger e context
      RuntimeConfig Config = getConfig();
                  
      // Inizializza variabili
      String StrProxyUserName = "";
      String StrProxyPassword = "";
      String StrProxyHost = "";
      int IntProxyPort = 0;
               
      // Prepara parametri proxy
      if (!Config.getString(REQUESTS_PROXY_MODE).equals("DIRECT")) {
      
         // Genera logging e acquisisce risorsa ESB proxy in formato XML
         Logger.logProperty(LogLevel.DEBUG,"Proxy Server Resource",Config.getString(REQUESTS_PROXY_PATH));                  
         XmlObject ObjProxyServer = OSBUtils.getResource("ProxyServer", Config.getString(REQUESTS_PROXY_PATH));

         // Esegue parsing dei vari parametri del proxy
         StrProxyHost = XMLUtils.getTextValue(ObjProxyServer, "//*:server/@host");
         IntProxyPort = Integer.valueOf(XMLUtils.getTextValue(ObjProxyServer, "//*:server/@port"));
         
         // Prepara autenticazione proxy
         if (!Config.getString(REQUESTS_PROXY_MODE).equals("ANONYMOUS")) {

             // Acquisisce credenziali
             StrProxyUserName = XMLUtils.getTextValue(ObjProxyServer, "//*:username/text()");
             StrProxyPassword = XMLUtils.getTextValue(ObjProxyServer, "//*:password/text()");
         }
      }
                            
      // Prepara i timeout (secondi), sostituendo i valori non positivi con il default per evitare attese infinite
      int IntConnectTimeout = Integer.parseInt(Config.getString(REQUESTS_CONN_TIMEOUT));
      int IntReadTimeout = Integer.parseInt(Config.getString(REQUESTS_READ_TIMEOUT));
      if (IntConnectTimeout<=0) IntConnectTimeout = DEFAULT_REQUESTS_TIMEOUT;
      if (IntReadTimeout<=0) IntReadTimeout = DEFAULT_REQUESTS_TIMEOUT;
      
      // Esegue fetch della risorsa
      return new String(HttpUtils.fetch(ObjHttpMethod,
                                        StrResourceURL,ObjRequestBody,
                                        StrRequestContentType,StrResponseContentType,
                                        StrHostAuthMode,StrHostUserName,StrHostPassword,  
                                        Config.getString(REQUESTS_PROXY_MODE),StrProxyUserName,StrProxyPassword,StrProxyHost,IntProxyPort, 
                                        Config.getString(REQUESTS_SSL_VERIFY).equals("ENABLE"), 
                                        IntConnectTimeout,
                                        IntReadTimeout,
                                        Logger));
   }
   
   // ==================================================================================================================================
   // Acquisisce logger di thread
   // ==================================================================================================================================    
   protected static LogManager getLogger() {      
      return ObjThreadLogger.get();   
   }    
   
   // ==================================================================================================================================
   // Crea logger di thread
   // ==================================================================================================================================    
   protected LogManager createLogger() {      
      LogManager ObjLogger = new LogManager(StrInstanceID);      
      ObjThreadLogger.set(ObjLogger);
      LogManager.defaultLogger.set(ObjLogger);
      return ObjLogger;   
   }   

   // ==================================================================================================================================
   // Acquisisce config di thread
   // ==================================================================================================================================    
   protected static RuntimeConfig getConfig() {      
      return ObjThreadConfig.get();   
   }    

   // ==================================================================================================================================
   // Crea nuova configurazione di thread in modalità outbound
   // ==================================================================================================================================    
   protected RuntimeConfig createConfig() {   
      
      // Prepara nuova config
      RuntimeConfig Config = new RuntimeConfig();     
      
      // Imposta varibile di trhead e restituisce referenza
      ObjThreadConfig.set(Config);
      return Config;   
   } 
   
   // ==================================================================================================================================
   // Acquisisce context di thread
   // ==================================================================================================================================    
   protected static RuntimeContext getContext() {      
      return ObjThreadContext.get();   
   }    

   // ==================================================================================================================================
   // Prepara context di thread condiviso da inbound/outbound
   // ==================================================================================================================================    
   protected RuntimeContext createContext(String StrContext,ServiceInfo ObjService) {    

      // Prepara nuovo context
      RuntimeContext Context = new RuntimeContext();     
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto statiche 
      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Contesto generale
      Context.put("uuid",UUID.randomUUID().toString());   
      Context.put("thread",String.valueOf(Thread.currentThread().getId()));   
      Context.put("context",StrContext);       
      Context.put("instance",StrInstanceID); 
      Context.put("providername",ObjProviderContext.providerName);   
      
      Context.put("request.counter",Thread.currentThread().getName());   
      Context.put("request.datetime",JavaUtils.getDateTime());          
      Context.put("request.timestamp",String.valueOf(JavaUtils.getTimestamp()));            

      // Contesto weblogic     
      Context.put("wls.realm",ObjProviderContext.realmName);   
      Context.put("wls.domain",ObjProviderContext.domainName);   
      Context.put("wls.managed",ObjProviderContext.managedName);   

      // Contesto java
      Context.put("java.version",String.valueOf(JavaUtils.getJavaVersion())); 
      
      // Contesto osb
      Context.put("osb.project",ObjService.getRef().getProjectName());  
      Context.put("osb.service.name",ObjService.getRef().getLocalName());      
      Context.put("osb.service.path",ObjService.getRef().getFullName());
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche semplici
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.put("current.epoch",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            return String.valueOf(System.currentTimeMillis()/1000); 
         }
      });              
      Context.put("current.datetime",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date(System.currentTimeMillis())); 
         }
      });              
      Context.put("current.timestamp",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            return String.valueOf(System.currentTimeMillis());
         }
      });   
      
      Context.put("token.header.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(Logger.formatProperties(LogLevel.DEBUG,ObjJwtToken.getHeader(),StringUtils.repeat(90,"-"),true)):("");
         }
      });                                                         
      Context.put("token.payload.*",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(Logger.formatProperties(LogLevel.DEBUG,ObjJwtToken.getPayload(),StringUtils.repeat(90,"-"),true)):("");
         }
      }); 
      Context.put("token.serialize",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            LogManager Logger = getLogger();
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?(ObjJwtToken.serialize()):("");
         }
      }); 
      
      // ----------------------------------------------------------------------------------------------------------------------------------
      // Prepara variabili di contesto dinamiche regex
      // ----------------------------------------------------------------------------------------------------------------------------------
      Context.putRegex("^token\\.header\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return ((ObjJwtToken!=null)&&(ObjJwtToken.isReady()))?((String) ObjJwtToken.getHeader().get(StrVariableName.split("\\.")[2])):("");
         }
      });       
      Context.putRegex("^token\\.payload\\.[^\\.]*$",new TemplateFunction() {
         public String apply(String StrVariableName,SuperMap ObjContext) throws Exception {
            JWTProvider ObjJwtToken = (JWTProvider) ObjContext.get("token"); 
            return (ObjJwtToken!=null)?((String) ObjJwtToken.getPayload().get(StrVariableName.split("\\.")[2])):("");
         }
      });     
      // ----------------------------------------------------------------------------------------------------------------------------------
      
      // Imposta varibile di trhead e restituisce referenza
      ObjThreadContext.set(Context);
      return Context;   
   }    
   
   // ==================================================================================================================================
   // Inizializza nome del thread (contatore di esecuzione)
   // ==================================================================================================================================
   protected synchronized void setThreadName()  {
      Thread.currentThread().setName(StringUtils.padLeft(String.valueOf(IntThreadCount++),7,"0"));
   }   
   
   // ==================================================================================================================================
   // Pulisce il thread context (richiamato in finally: config e context possono mancare se la richiesta e' fallita prima di crearli)
   // ==================================================================================================================================
   protected void cleanThread() {

      RuntimeConfig Config = ObjThreadConfig.get();
      if (Config!=null) Config.clear();

      RuntimeContext Context = ObjThreadContext.get();
      if (Context!=null) Context.clear();

      ObjThreadLogger.remove();
      ObjThreadConfig.remove();
      ObjThreadContext.remove(); 
      
      LogManager.defaultLogger.remove();
   } 
      
   // ==================================================================================================================================
   // Acquisisce provider
   // ==================================================================================================================================    
   protected abstract ProviderMBean getProviderMBean();
   
   // ==================================================================================================================================
   // Acquisisce puntatore al provider
   // ==================================================================================================================================    
   protected Object getProviderMBeanAttribute(String StrAttributeName) throws Exception {
      Method ObjMethod = ObjProviderContext.providerMBean.getClass().getMethod("get"+StrAttributeName);
      return ObjMethod.invoke(ObjProviderContext.providerMBean);
   }   
}
