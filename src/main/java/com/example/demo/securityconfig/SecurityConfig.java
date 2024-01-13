    package com.example.demo.securityconfig;

    import com.example.demo.Controllers.ApiUser;
    import com.example.demo.model.User;
    import com.example.demo.repository.UserRepository;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.config.Customizer;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
    import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
    import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
    import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
    import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
    import org.springframework.security.oauth2.core.oidc.user.OidcUser;
    import org.springframework.security.oauth2.core.user.OAuth2User;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

    import java.util.ArrayList;
    import java.util.Collections;
    import java.util.List;


    @Configuration
    @EnableWebSecurity
    public class SecurityConfig  {

        @Autowired
        private ApiUser userApi;

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }



        /*
        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(
                    User.withUsername("user")
                            .password(passwordEncoder().encode("123"))
                            .roles("USER")
                            .build(),
                    User.withUsername("admin")
                            .password(passwordEncoder().encode("123"))
                            .roles("ADMIN")
                            .build()
            );
        }

    */





        @Bean
        public UserDetailsService userDetailsService() {
            return new UserDetailsService() {
                @Override
                public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


                    com.example.demo.model.User user = userApi.searchbyUserName(username);


                    if (user == null) {

                        throw new UsernameNotFoundException("Usuario no encontrado: " + username);

                    }

                    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
                    String hashedPassword = encoder.encode(user.getPassword());



                    return org.springframework.security.core.userdetails.User
                            .withUsername(user.getUsername())
                            .password(hashedPassword)
                            .roles(user.getRol())
                            .build();
                }
            };
        }







      /*  @Bean
        SecurityFilterChain security(HttpSecurity security) throws Exception {
            return  security
                    .formLogin(form -> form
                            .permitAll()
                            .defaultSuccessUrl("/home.html", true) // Redirigir a home.html después de un inicio de sesión exitoso
                    )
                    .authorizeHttpRequests((auth -> auth.anyRequest().authenticated()))
                    .build();
        }

       */


        @Bean
        SecurityFilterChain security(HttpSecurity securityy) throws Exception {
            return securityy.csrf().disable()

                    .oauth2Login(oauth2 -> oauth2
                            .loginPage("/login")
                            .defaultSuccessUrl("/users")

                            .failureHandler((request, response, exception) -> {
                                String errorMsg = exception.getMessage();
                                System.out.println(errorMsg);
                                // obtener detalles del error
                                response.sendRedirect("/login?error");
                            })
                            .successHandler((request, response, authentication) -> {


                                String userEmail = null;
                                String username = null;

                                if (authentication.getPrincipal() instanceof DefaultOidcUser) {
                                    DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
                                    userEmail = oidcUser.getEmail();
                                }

                                if (userEmail != null && !userEmail.isEmpty()) {


                                    User user = userApi.searchByemail(userEmail);

                                    if (user == null) {

                                        response.sendRedirect("/login?error");
                                    } else {


                                        username = user.getUsername();

                                        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                                                .username(username)
                                                .password("")
                                                .authorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))
                                                .build();


                                        Authentication newAuth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                                        SecurityContextHolder.getContext().setAuthentication(newAuth);

                                        response.sendRedirect("/users");


                                    }


                                }
                            })


                    )
                    .formLogin(form -> form
                            .loginPage("/login")
                            .usernameParameter("username").passwordParameter("password")
                            .permitAll()

                            .defaultSuccessUrl("/users", true)
                            .failureUrl("/login?error")
                            .successHandler((request, response, authentication) -> {
                                // Obtener el rol del usuario autenticado
                                String role = authentication.getAuthorities().iterator().next().getAuthority();
                                System.out.println("Rol del usuario autenticado: " + role);

                                // Redirigir a una página según el rol (opcional)
                                if ("ROLE_ADMIN".equals(role)) {
                                    response.sendRedirect("/");
                                } else {
                                    response.sendRedirect("/users");
                                }
                            })
                    )

                    .authorizeRequests(authorize ->
                            authorize
                                    .requestMatchers("/").hasAuthority("ROLE_ADMIN")
                                    .requestMatchers("/users").hasAuthority("ROLE_USER")
                                    .requestMatchers("/mobile/**").permitAll()
                                    .anyRequest().authenticated()
                    )
                    .build();
        }

        private OidcUserService oidcUserService() {
            return new OidcUserService();
        }





        /*
        @Bean<
        SecurityFilterChain security(HttpSecurity securityy) throws Exception {
            return  securityy
                    .formLogin(form -> form
                            .loginPage("/login.html")
                            .permitAll()
                            .defaultSuccessUrl("/home.html", true) // Redirigir a home.html después de un inicio de sesión exitoso
                    )
                    .authorizeHttpRequests((auth -> auth.anyRequest().authenticated()))
                    .build();
        }

         */


    /*
    @Bean
    public SecurityFilterChain filterchain(HttpSecurity httsecurity) throws Exception {
        return httsecurity
                .csrf().disable().build();
    }
    */



    }
