# Experiment Summary

This experiment focuses on modernizing authentication configuration during a migration from Spring Boot 2.7 to Spring Boot 3, specifically addressing the use of the deprecated `configure(AuthenticationManagerBuilder)` method.

In Spring Security 5.7+, overriding `configure(AuthenticationManagerBuilder)` is discouraged, and in Spring Security 6 (used by Spring Boot 3+), `WebSecurityConfigurerAdapter`, which enables this override has been removed entirely.

The goal of this test is to determine whether the LLM can:
- Detect the usage of deprecated authentication configuration
- Replace it with a valid, bean-based `UserDetailsService` and `PasswordEncoder` setup
- Maintain equivalent in-memory authentication behavior


## Code to be migrated (Spring Boot 2)

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

```

## Expected solution
```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder.encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```

## diff view
```diff
@@ Code to be migrated (Spring Boot 2) vs Expected solution (Spring Boot 3) @@
-import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
-import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
-import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
+import org.springframework.security.core.userdetails.User;
+import org.springframework.security.core.userdetails.UserDetails;
+import org.springframework.security.core.userdetails.UserDetailsService;
+import org.springframework.security.provisioning.InMemoryUserDetailsManager;

 @Configuration
-@EnableWebSecurity
-public class SecurityConfig extends WebSecurityConfigurerAdapter {
-    @Override
-    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
-        auth.inMemoryAuthentication()
-            .withUser("user")
-            .password(passwordEncoder().encode("password"))
-            .roles("USER");
-    }
+public class SecurityConfig {

     @Bean
     public PasswordEncoder passwordEncoder() {
         return new BCryptPasswordEncoder();
     }

+    @Bean
+    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
+        UserDetails user = User.builder()
+            .username("user")
+            .password(passwordEncoder.encode("password"))
+            .roles("USER")
+            .build();
+        return new InMemoryUserDetailsManager(user);
+    }
 }

```

## Experiments

### GPT-4o-mini

#### Hint strategy

The LLM was provided with the full Spring Boot 2 code snippet that included an override of `configure(AuthenticationManagerBuilder)` inside a class extending `WebSecurityConfigurerAdapter`. A rule message was given stating that overriding this method is discouraged as of Spring Security 5.7 and recommending the use of a `UserDetailsService` and `PasswordEncoder` bean instead. In addition to this, an example code before and after were provided.

This example's results are used in the good hint experimentation of other models.

The LLM retuned the following in addition to the refactored code,

* Step-by-Step Migration Process
* Summary of Changes
* Hint for Migration

##### Refactored Code

``` java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();
        return http.build();
    }
}

```

#### Observation

While it refactored the code well with given inputs, it still did not follow best practices. This could be because of lack of context or more examples. The summary of chnages section is used in other experiments.

### GPT-3.5-Turbo

#### No hint experimentation

The LLM was provided with the full Spring Boot 2 code snippet that included an override of `configure(AuthenticationManagerBuilder)` inside a class extending `WebSecurityConfigurerAdapter`. A rule message was given stating that overriding this method is discouraged as of Spring Security 5.7 and recommending the use of a `UserDetailsService` and `PasswordEncoder` bean instead. 

The LLM retuned the refactored code and a Hint for Migration

##### Refactored code

``` java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

##### Observation

The LLM failed to fully implement the correct migration. While it retained the PasswordEncoder bean, the solution,

* Did not remove the deprecated `WebSecurityConfigurerAdapter` class.
* Did not replace the deprecated `configure(AuthenticationManagerBuilder)` method with `UserDetailsService` bean
* No update to the original in-memory user authentication behavior.
* Ignored the provided rule hint recommending the use of `UserDetailsService`.

#### Poor hint experimentation

The LLM was provided with the full Spring Boot 2 code snippet that included an override of `configure(AuthenticationManagerBuilder)` inside a class extending `WebSecurityConfigurerAdapter`. A rule message was given stating that overriding this method is discouraged as of Spring Security 5.7 and recommending the use of a `UserDetailsService` and `PasswordEncoder` bean instead. An example of similar problem that has before and after snippet was provided.

The LLM retuned the refactored code and a Hint for Migration

##### Refactored code

``` java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

##### Observation

The LLM implemented the `UserDetailsService` and `PasswordEncoder` beans as suggested in the rule and example, but, it failed to remove the deprecated `WebSecurityConfigurerAdapter`, which was necessary.

#### Good hint experimentation

The LLM was provided with the full Spring Boot 2 code snippet that included an override of `configure(AuthenticationManagerBuilder)` inside a class extending `WebSecurityConfigurerAdapter`. A rule message was given stating that overriding this method is discouraged as of Spring Security 5.7 and recommending the use of a `UserDetailsService` and `PasswordEncoder` bean instead. An example of similar problem that has before and after snippet and a summary of changes from gpt-4o-mini result were also provided.

The LLM retuned the refactored code and a Hint for Migration

##### Refactored code

``` java

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorizeRequests ->
                authorizeRequests
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults());
        return http.build();
    }
}

```

##### Observation

LLM updated the code correctly but doesnt follow best practices. It also added the function `public SecurityFilterChain securityFilterChain(HttpSecurity http) ` that has missing imports and deprectaed methods.