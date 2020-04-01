package org.zerhusen.security.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.zerhusen.security.jwt.TokenProvider;
import org.zerhusen.security.rest.dto.LoginDto;

import javax.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class AuthenticationRestController {

   private final TokenProvider tokenProvider;

   private final AuthenticationManagerBuilder authenticationManagerBuilder;
   private RestTemplate restTemplate;

   public AuthenticationRestController(TokenProvider tokenProvider,
                                       AuthenticationManagerBuilder authenticationManagerBuilder,
                                       RestTemplate restTemplate) {
      this.tokenProvider = tokenProvider;
      this.authenticationManagerBuilder = authenticationManagerBuilder;
      this.restTemplate = restTemplate;
   }

   @PostMapping("/authenticate")
   public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginDto loginDto) {
      UsernamePasswordAuthenticationToken authenticationToken =
         new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

      Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      String jwt = tokenProvider.createToken(authentication);

      return new ResponseEntity<>(new JWTToken(jwt), HttpStatus.OK);
   }

   @PostMapping("send-sms")
   public void SendSMS() throws URISyntaxException {
      CinchSMSBody cinchSMSBody = new CinchSMSBody("14322946147",
         List.of("15853178336"),
         "This is a test message from your Sinch account again"
      );

      HttpHeaders headers = new HttpHeaders();
      headers.set("Authorization", "Bearer 928325e85e294125a20c8d1b3405d8aa");
      headers.set("Content-Type", "application/json");

      HttpEntity<CinchSMSBody> request = new HttpEntity<>(cinchSMSBody, headers);

      URI url = new URI("https://sms.api.sinch.com/xms/v1/6b11e28ad61440cf95e1e8204a72d977/batches");
      String response = restTemplate.postForObject(url, request, String.class);
//      ResponseBean response = restTemplate.postForObject(url, request, ResponseBean.class);
   }

   static class JWTToken {
      private String idToken;

      JWTToken(String idToken) {
         this.idToken = idToken;
      }

      @JsonProperty("id_token")
      String getIdToken() {
         return idToken;
      }

      void setIdToken(String idToken) {
         this.idToken = idToken;
      }
   }

   static class CinchSMSBody {
      private String from;
      private List<String> to;
      private String body;

      public CinchSMSBody() {
      }

      public CinchSMSBody(String from, List<String> to, String body) {
         this.from = from;
         this.to = to;
         this.body = body;
      }

      public String getFrom() {
         return from;
      }

      public void setFrom(String from) {
         this.from = from;
      }

      public List<String> getTo() {
         return to;
      }

      public void setTo(List<String> to) {
         this.to = to;
      }

      public String getBody() {
         return body;
      }

      public void setBody(String body) {
         this.body = body;
      }
   }
}
