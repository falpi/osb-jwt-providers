// ##################################################################################################################################
// VERSIONING
// ##################################################################################################################################
// $Revision: 1970 $
// $Date: 2026-05-19 15:04:47 +0200 (Tue, 19 May 2026) $
// ##################################################################################################################################

package org.falpi.osb.security.providers;

// ##################################################################################################################################
// Referenze
// ##################################################################################################################################

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

class CustomInboundAuthenticatorCallbackHandler implements CallbackHandler {
   private String StrUserName;

   CustomInboundAuthenticatorCallbackHandler(String StrUser) {
      StrUserName = StrUser;
   }

   @Override
   public void handle(Callback[] ArrCallbacks) throws UnsupportedCallbackException {
      for (int i = 0; i < ArrCallbacks.length; i++) {
         Callback ObjCallback = ArrCallbacks[i];
         if (!(ObjCallback instanceof NameCallback)) {
            throw new UnsupportedCallbackException(ObjCallback, "Unrecognized Callback");
         }
         NameCallback nameCallback = (NameCallback) ObjCallback;
         nameCallback.setName(StrUserName);
      }
   }
}