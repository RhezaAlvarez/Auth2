package com.tujuhsembilan.example.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.tujuhsembilan.example.configuration.property.AuthProp;
import com.tujuhsembilan.example.model.Token;
import com.tujuhsembilan.example.repository.TokenRepo;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class BasicLoginController {

  private final ObjectMapper objMap;

  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;
  private final AuthProp authProp;

  private final ECKey ecJwk;

  @Autowired
  private TokenRepo tokenRepo;

  @GetMapping("/jwks.json")
  public ResponseEntity<?> jwk() throws JsonProcessingException {
    return ResponseEntity.ok(Map.of("keys", Set.of(objMap.readTree(ecJwk.toPublicJWK().toJSONString()))));
  }

  // You MUST login using BASIC AUTH, NOT POST BODY
  @PostMapping("/login")
  public ResponseEntity<?> login(@NotNull Authentication auth, @RequestParam(name = "rememberMe", defaultValue = "false") boolean rememberMe) {
    List<Token> tokens = tokenRepo.findAll();
    Instant now = Instant.now();

    Integer accessTokenExpiredDuration = rememberMe ? authProp.getACCESS_TOKEN_DURATION_REMEMBER_ME() : authProp.getACCESS_TOKEN_DURATION_NOT_REMEMBER_ME();
    Instant accessTokenExpiredTime = now.plus(accessTokenExpiredDuration , ChronoUnit.SECONDS);

    var accessToken = jwtEncoder
    .encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
        JwtClaimsSet.builder()
            .issuer(authProp.getUuid())
            .audience(List.of(authProp.getUuid()))
            .subject(((User) auth.getPrincipal()).getUsername())
            // You SHOULD set expiration, claims, etc here too
            .expiresAt(accessTokenExpiredTime)
            .build()));

    Token accessTokenTemp = new Token(accessToken.getTokenValue(), auth.getName(), true);
    tokenRepo.save(accessTokenTemp);

    Integer refreshTokenExpiredDuration = accessTokenExpiredDuration * 2;
    Instant refreshTokenExpiredTime = now.plus(refreshTokenExpiredDuration , ChronoUnit.SECONDS);
    
    var refreshToken = jwtEncoder
        .encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
            JwtClaimsSet.builder()
                .issuer(authProp.getUuid())
                .audience(List.of(authProp.getUuid()))
                .subject(((User) auth.getPrincipal()).getUsername())
                // You SHOULD set expiration, claims, etc here too
                .expiresAt(refreshTokenExpiredTime)
                .build()));
    
    Token refreshTokenTemp = new Token(accessToken.getTokenValue(), auth.getName(), true);
    tokenRepo.save(refreshTokenTemp);

    tokens.stream().forEach(token -> {
      if(token.getUsername().equals(auth.getName()) && token.getIsActive() == true){
        token.setIsActive(false);
      }
    });

    return ResponseEntity.ok(Map.of(
      "accessToken", accessToken.getTokenValue(),
      "refreshToken", refreshToken.getTokenValue()
    ));
  }
  
  @PostMapping("/refresh-token")
  public ResponseEntity<?> refreshToken(@RequestBody String refreshToken, @RequestParam(name = "rememberMe", defaultValue = "false") boolean rememberMe) {
    try {
        Jwt decodedToken = jwtDecoder.decode(refreshToken);

        if (decodedToken == null || decodedToken.getExpiresAt().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token");
        }

        Instant now = Instant.now();
        Integer newAccessTokenDuration = rememberMe ? authProp.getACCESS_TOKEN_DURATION_REMEMBER_ME() : authProp.getACCESS_TOKEN_DURATION_NOT_REMEMBER_ME();
        Instant newAcccessTokenExpireTime = now.plus(newAccessTokenDuration, ChronoUnit.SECONDS);

        var newAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(
            JwsHeader.with(SignatureAlgorithm.ES512).build(),
            JwtClaimsSet.builder()
                .issuer(authProp.getUuid())
                .audience(List.of(authProp.getUuid()))
                .subject(decodedToken.getSubject())
                .expiresAt(newAcccessTokenExpireTime)
                .build()
        ));

        return ResponseEntity.ok(newAccessToken.getTokenValue());
    } catch (JwtException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
    }
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout(Authentication authentication) {
    if (authentication instanceof JwtAuthenticationToken) {
      String username = authentication.getName();

      List<Token> listToken = tokenRepo.findAll();
      listToken.stream().forEach(token ->{
        if(token.getUsername().equals(username)){
          token.setIsActive(false);
        }
      });
    }
    return ResponseEntity.ok().build();
  }

}
