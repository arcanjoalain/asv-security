package br.com.asv.security.jwt;

import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.com.asv.security.models.IEntitySecurity;
import br.com.asv.security.models.JWTokenResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;

/*
 * JWTProperties Helper Class
 * Generates token, read configurations from properties file, etc.
 */
@Component
@Data
public class JWTokenService<I> {

    @Autowired
    private JWTProperties properties;

    public Long getExpirationSenhaTemporaria() {
        return properties.getExpirationSenhaTemporaria();
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + (properties.getExpiresIn() * 60000)))
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact();
    }

    public String generateToken(IEntitySecurity<I> user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername()).setId(user.getPid().toString());
        claims.put("username", user.getUsername());
//        claims.put("profile", user.getProfile().getRules().stream().map(Rules::toString).collect(Collectors.toList()));
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + (properties.getExpiresIn() * 60000)))
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact();
    }
    
    public JWTokenResult generateTokenObj(IEntitySecurity<I> user) {
    	JWTokenResult jwTokenResult =new JWTokenResult();
        Claims claims = Jwts.claims().setSubject(user.getUsername()).setId(user.getPid().toString());
        claims.put("username", user.getUsername());
//        claims.put("profile", user.getProfile().getRules().stream().map(Rules::toString).collect(Collectors.toList()));
        jwTokenResult.setDateExpire(new Date(System.currentTimeMillis() + (properties.getExpiresIn() * 60000)));
        jwTokenResult.setToken(Jwts.builder()
                .setClaims(claims)
                .setExpiration(jwTokenResult.getDateExpire())
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact());
        
        return jwTokenResult;
    }

    public String generateTokenSenhaTemporaria(IEntitySecurity<I> user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername()).setId(user.getPid().toString());
        claims.put("username", user.getUsername());
//        claims.put("authorities", user.getProfile().getRules().stream().map(Rules::toString).collect(Collectors.toList()));
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + (properties.getExpirationSenhaTemporaria() * 60000)))
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact();
    }
    
    public JWTokenResult generateTokenSenhaTemporariaObj(IEntitySecurity<I> user) {
    	JWTokenResult jwTokenResult =new JWTokenResult();
        Claims claims = Jwts.claims().setSubject(user.getUsername()).setId(user.getPid().toString());
        claims.put("username", user.getUsername());
//        claims.put("authorities", user.getProfile().getRules().stream().map(Rules::toString).collect(Collectors.toList()));
        jwTokenResult.setDateExpire(new Date(System.currentTimeMillis() + (properties.getExpirationSenhaTemporaria() * 60000)));
        jwTokenResult.setToken(Jwts.builder()
                .setClaims(claims)
                .setExpiration(jwTokenResult.getDateExpire())
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact());
        return jwTokenResult;
    }
    
    public String generateTokenDevice(IEntitySecurity<I> dto) {
        return Jwts.builder()
                .setSubject(dto.getPid().toString())
                .signWith( SignatureAlgorithm.HS512, properties.getSecret().getBytes())
                .compact();
    }

    public boolean tokenValido(String token) {
        Claims claims = getClaims(token);
        if(claims != null) {
            String username = claims.getSubject();
            Date expirionDate = claims.getExpiration();
            Date now = new Date(System.currentTimeMillis());
            if(username != null && expirionDate != null && now.before(expirionDate)) {
                return true;
            }
        }
        return false;
    }

    public String getSubject(String token) {
        return getClaims(token).getSubject();
    }

    public String getUsername(String token) {
        Claims claims = getClaims(token);
        if(claims != null) {
            return claims.getSubject();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public List<String> getAuthorities(String token) {
        Claims claims = getClaims(token);
        if(claims != null) {
            return claims.get("authorities", List.class);
        }
        return null;
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(properties.getSecret().getBytes()).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}