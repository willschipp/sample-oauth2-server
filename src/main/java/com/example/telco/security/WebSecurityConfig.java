package com.example.telco.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    //TODO - this is hard coded! should be externalized for production

    /**
     * sets our users using an in-memory store and hard coded credentials BAD!!!!
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("jdoe").password(passwordEncoder.encode("welcome1")).roles("USER");
    }

    /**
     * uses the default auth manager bean
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * sets up our access control and protected endpoints
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login").permitAll()
                .antMatchers("/tokens/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin().permitAll()
                .and().csrf().disable();
    }
}
