package org.zerhusen.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;

@RestController
@RequestMapping("/api")
public class AdminProtectedRestController {

   @Secured("ROLE_ADMIN")
   @GetMapping("/hiddenmessage")
   public ResponseEntity<HiddenMessage> getAdminProtectedGreeting(@AuthenticationPrincipal User user) {
      return ResponseEntity.ok(new HiddenMessage("this is a hidden message!"));
   }

   private static class HiddenMessage {

      private final String message;

      private HiddenMessage(String message) {
         this.message = message;
      }

      public String getMessage() {
         return message;
      }
   }
}
