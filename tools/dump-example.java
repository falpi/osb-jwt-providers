try { 
   java.io.PrintStream dumpOut;
   System.out.println("=========================================================================================");
   System.out.println("=== DUMP SENDER XML ====================================================================");
   System.out.println("=========================================================================================");
   dumpOut = new java.io.PrintStream(new java.io.FileOutputStream("C:/temp/osb-dump-sender.xml", false));
   dumpOut.println("<!-- DUMP " + new java.util.Date() + " -->");
   DumpUtils.dumpObjectToXml(ObjSender,false, dumpOut,
                             "jdk.",
                             "java.",
                             "javax.",
                             "sun.",
                             "com.sun.",
                             "net.java.",
                             "weblogic.",
                             "oracle.",
                             "com.oracle.",
                             "com.ctc.wstx.",
                             "org.glassfish.",
                             "org.apache.xmlbeans.",
                             "com.bea.xbean.",                                   
                             "com.bea.wli.config.",
                             //"com.bea.wli.config.Ref",
                             //"com.bea.wli.config.impl.",
                             //"com.bea.wli.config.resource.",
                             //"com.bea.wli.config.component.impl."
                             "com.bea.wli.monitoring.",
                             "com.bea.wli.sb.resources.");
   dumpOut.close();
} catch (Exception e) {
   System.out.println("eccezione:" + e.getMessage());
}