package elliott.pope.authmechanisms.controller;

import elliott.pope.authmechanisms.TestMultipleAuthRunner;
import elliott.pope.authmechanisms.utils.CertificateUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {TestMultipleAuthRunner.class})
@AutoConfigureMockMvc
public class TestControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void test__Unauthenticated__OpenEndpoint() throws Exception {
        mvc.perform(get("/test"))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    public void test__Unauthenticated__ClosedEndpoint() throws Exception {
        mvc.perform(get("/test/authenticate")
                .secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void test__BasicAuth__ClosedEndpoint() throws Exception {
        mvc.perform(get("/test/authenticate")
                .secure(true)
                .with(user("test-user-basic").password("test-password")))
                .andExpect(status().isOk())
                .andExpect(content().string("test-user-basic"));
    }

    @Test
    public void test__BasicAuth__X509User() throws Exception {
        mvc.perform(get("/test/authenticate")
                .secure(true)
                .with(user("test-user-x509")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void test__X509Auth__ClosedEndpoint() throws Exception {
        mvc.perform(get("/test/authenticate")
                .secure(true)
                .with(x509(CertificateUtils.generate("test-user-x509", 1))))
                .andExpect(status().isOk())
                .andExpect(content().string("test-user-x509"));
    }

    @Test
    public void test__X509Auth__BasicAuthUser() throws Exception {
        mvc.perform(get("/test/authenticate")
                .secure(true)
                .with(x509(CertificateUtils.generate("test-user-basic", 1))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void test__X509Auth__X509OnlyEndpoint() throws Exception {
        mvc.perform(get("/test/authenticate/x509")
                .secure(true)
                .with(x509(CertificateUtils.generate("test-user-x509", 1))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("test-user-x509"));
    }

    @Test
    public void test__BasicAuth__X509OnlyEndpoint() throws Exception {
        mvc.perform(get("/test/authenticate/x509")
                .secure(true)
                .with(user("test-user-basic").password("test-password")))
                .andDo(print())
                .andExpect(status().isForbidden());
    }


}
