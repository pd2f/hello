package hello;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;

@Configuration
public class MvcConfig implements org.springframework.web.servlet.config.annotation.WebMvcConfigurer
{
  public MvcConfig() {}
  
  public void addViewControllers(ViewControllerRegistry registry) {
    registry.addViewController("/home").setViewName("home");
    registry.addViewController("/").setViewName("index");
    registry.addViewController("/hello").setViewName("hello");
    registry.addViewController("/login").setViewName("login");
    registry.addViewController("/usuario").setViewName("usuario");
  }
}
