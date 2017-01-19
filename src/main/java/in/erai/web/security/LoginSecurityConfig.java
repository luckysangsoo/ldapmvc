package in.erai.web.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
@Configuration
@EnableWebSecurity
@PropertySource("classpath:ldap.properties")
public class LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    //@Value("ldap://localhost:10389")
    @Value("ldap://${ldap.host}:${ldap.port}")
    private String url;

    //@Value("uid=admin,ou=system")
    @Value("${ldap.user}")
    private String user;

    //@Value("secret")
    @Value("${ldap.password}")
    private String password;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {

        List<String> userGroups = new ArrayList<>();
        userGroups.add("uid={0},ou=users");

        authenticationMgr.ldapAuthentication()
        .userSearchFilter("(uid={0})")


        .userSearchBase("ou=users,ou=system")
        .groupSearchFilter("(uniqueMember={0})")
        .groupSearchBase("ou=users,ou=system")
        .contextSource(ldapContextSource());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
        .antMatchers("/homePage")
        .fullyAuthenticated()
        .and()
            .formLogin().loginPage("/loginPage")
            .defaultSuccessUrl("/homePage")
            .failureUrl("/loginPage?error")
            .usernameParameter("username").passwordParameter("password")
        .and()
            .logout().logoutSuccessUrl("/loginPage?logout");

    }
    @Bean
    public LdapContextSource  ldapContextSource() {

        LdapContextSource bean = new LdapContextSource();
        bean.setUrl(url);
        bean.setUserDn(user);
        bean.setPassword(password);
        bean.afterPropertiesSet();

        return bean;
    }
    @Bean
    public static PropertySourcesPlaceholderConfigurer placeHolderConfigurer() {
     return new PropertySourcesPlaceholderConfigurer();
    }
}
