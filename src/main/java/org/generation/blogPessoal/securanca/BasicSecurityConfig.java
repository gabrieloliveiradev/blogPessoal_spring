package org.generation.blogPessoal.securanca;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {
		
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.authorizeRequests()
		.antMatchers("/usuarios/logar").permitAll()
		.antMatchers("/usuarios/cadastrar").permitAll()//serve pra liberar alguns caminhos(endpoints) dentro do controller onde o cliente tem acesso a ele sem precisar passar um token(o endpoint liberado aqui foi o /usuarios/logar e o /usuarios/cadastrar)
		.anyRequest().authenticated() //diz que todas as outras requisições além das de cima precisarão ser autenticadas
		.and().httpBasic() //vai utilizar o padrão basic pra gerar a chave token
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //vai indicar qual tipo de sessão iremos utilizar nesse caso será STATLESS(ou seja não irá guardar sessão)
		.and().cors() //habilita o cors
		.and().csrf().disable(); 
	} 
	
	
}
