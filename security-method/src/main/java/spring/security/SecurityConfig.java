package spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/css/**", "/index", "/console/**").permitAll()
			.antMatchers("/user/**").authenticated()
			.and()
			.formLogin().loginPage("/login").failureUrl("/login-error")
			.and().exceptionHandling().accessDeniedPage("/error");
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("invalid").password("123").roles("INVALID")
			.and().withUser("user").password("123").roles("USER")
			.and().withUser("admin").password("123").roles("SUPERADMIN", "USER");
	}
}