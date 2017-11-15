package spring.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/css/**", "/index", "/console/**").permitAll()
			.antMatchers("/user/**").hasAuthority("SUPERADMIN")
			.and()
			.formLogin().loginPage("/login").failureUrl("/login-error")
			.and().exceptionHandling().accessDeniedPage("/error")
			.and()
			.csrf().disable()
			.headers().frameOptions().disable();
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
				.usersByUsernameQuery("select username,password,enabled from users where username=?")
				.authoritiesByUsernameQuery("select username, authority from authorities where username=?");
	}
}