package com.example.demo.securityconfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@Component
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final String secretKey = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxODUwNzAwMzM1IiwiaWF0IjoxNzA1MDQxNDg0fQ.oxRyvNlix9TpNHbASSZS-F-kNhbUrN09GB0cNTn48ZU";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return !path.startsWith("/rest");
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        String path = request.getRequestURI();
        System.out.println("ENTREEEEEEASDA ");
        // Solo procesar el token JWT si la ruta comienza con "/rest"
        if (path.startsWith("/rest")) {
            if (header != null && header.startsWith("Bearer")) {
                String token = header.replace("Bearer", "");

                System.out.println("ENTREEEEEE "+ token);

                try {
                    // Solo verifica que el token es válido


                    if (token.equals(this.secretKey)){
                        System.out.println("VALIDADO");
                        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                                null, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                        );

                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }else{

                        System.out.println( " NO VALIDADO");

                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                        return;
                    }

                } catch (Exception e) {
                    // Si el token es inválido, termina la solicitud con un error 401
                    System.out.println( " NO VALIDADO");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }

}