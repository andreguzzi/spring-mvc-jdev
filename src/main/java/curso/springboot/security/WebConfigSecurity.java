package curso.springboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;

	@Override // Configura as solicitacoes de acesso por http
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable() // Desativa as configurações padrao de memoria
				.authorizeRequests() // permitir restringir acessos
				.antMatchers(HttpMethod.GET, "/").permitAll() // Qualquer usuario acessa a pagina
				.antMatchers("**/materialize/**").permitAll().antMatchers(HttpMethod.GET, "/cadastropessoa")
				.hasAnyRole("ADMIN").anyRequest().authenticated().and().formLogin().permitAll() // permite qualquer
																								// usuario
				.loginPage("/login").defaultSuccessUrl("/cadastropessoa").failureUrl("/login?error=true").and().logout()
				.logoutSuccessUrl("/login") // mapeia url de logout e invalida usuario autenticado
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}

	@Override // cria autenticação do usuario com o banco de dados ou memoria
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(implementacaoUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());

		/*
		 * auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
		 * .withUser("andre")
		 * .password("$2a$10$e7ec8u/ezHHi2FWo4rL2IevGHbF86ilwccqQ2KK7a4l6toDPFFFXu")
		 * .roles("ADMIN");
		 */
	}

	@Override // Ignora URL especificas
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/materialize/**").antMatchers(HttpMethod.GET, "/resources/**", "/static/**",
				"/materialize/**", "**/materialize/**");
	}

}
