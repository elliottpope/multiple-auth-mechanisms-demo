package elliott.pope.authmechanisms.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    private static String nullsafePrincipalName(Principal principal) {
        return principal == null ? "" : principal.getName();
    }

    @GetMapping("/test")
    public String testEndpoint(Principal principal) {
        return nullsafePrincipalName(principal);
    }

    @GetMapping("/test/authenticate")
    public String testEndpointAuthenticate(Principal principal) {
        return nullsafePrincipalName(principal);
    }

    @GetMapping("/test/authenticate/x509")
    @PostAuthorize("hasAuthority('X509')")
    public String testOnlyX509Auth(Principal principal) {return nullsafePrincipalName(principal);}

    @GetMapping("/test/authenticate/basic")
    @PostAuthorize("hasRole('Basic')")
    public String testOnlyBasicAuth(Principal principal) {return nullsafePrincipalName(principal);}

}
