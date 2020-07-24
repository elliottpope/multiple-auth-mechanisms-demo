package elliott.pope.authmechanisms.configuration;

import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests().antMatchers("/test").permitAll()
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .x509()
                .userDetailsService(s -> {
                    if ("test-user-x509".equals(s)) {
                        return new User("test-user-x509", "", Collections.singleton(new SimpleGrantedAuthority("X509")));
                    }
                    throw new BadCredentialsException("User " + s + " not found.");
                })
                .and()
                .addFilterAfter(new TokenAuthenticationFilter(), X509AuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
                .passwordEncoder(encoder)
                .withUser("test-user-basic")
                .password(encoder.encode("test-password"))
                .roles("USER");
    }

    public static class TokenAuthenticationFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            boolean debug = this.logger.isDebugEnabled();
            String header = request.getHeader("Authorization");
            if (header != null && header.toLowerCase().startsWith("token ")) {
                try {
                    String token = header.substring("token ".length());
                    if (debug) {
                        this.logger.debug("Basic Authentication Authorization header found for token '" + token + "'");
                    }

                    PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken((Principal) () -> "Client", token);
                    Authentication authResult = new TokenAuthenticationManager().authenticate(authRequest);
                    if (debug) {
                        this.logger.debug("Authentication success: " + authResult);
                    }

                    SecurityContextHolder.getContext().setAuthentication(authResult);
                } catch (AuthenticationException var10) {
                    SecurityContextHolder.clearContext();
                    if (debug) {
                        this.logger.debug("Authentication request for failed: " + var10);
                    }
                    chain.doFilter(request, response);
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }

    public static class TokenAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if ("test-token".equals(authentication.getCredentials()) &&
                    "Client".equals(((Principal) authentication.getPrincipal()).getName())) {
                return new PreAuthenticatedAuthenticationToken("Client", "test-token", Collections.singleton(new SimpleGrantedAuthority("Token")));
            }
            throw new BadCredentialsException("No user found for " + authentication.getCredentials());
        }
    }

    @Bean
    public ErrorAttributes errorAttributes() {
        return new DefaultErrorAttributes();
    }

    @Bean
    public ErrorProperties errorProperties() {
        return new ErrorProperties();
    }
}

