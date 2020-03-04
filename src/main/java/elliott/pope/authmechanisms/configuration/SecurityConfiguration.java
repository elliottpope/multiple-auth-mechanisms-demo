package elliott.pope.authmechanisms.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

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
                    throw new UsernameNotFoundException("User " + s + " not found.");
                });
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
}
