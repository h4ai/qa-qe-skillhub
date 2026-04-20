package com.iflytek.skillhub.auth.ldap;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

import com.iflytek.skillhub.auth.config.LdapProperties;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.LdapTemplate;

@ExtendWith(MockitoExtension.class)
class LdapAuthServiceTest {

    @Mock
    private LdapProperties ldapProperties;

    @Mock
    private LdapTemplate ldapTemplate;

    @Mock
    private UserAccountRepository userAccountRepository;

    @Mock
    private UserRoleBindingRepository userRoleBindingRepository;

    @Mock
    private GlobalNamespaceMembershipService globalNamespaceMembershipService;

    private LdapAuthService service;

    @BeforeEach
    void setUp() {
        service = new LdapAuthService(
            ldapProperties,
            ldapTemplate,
            userAccountRepository,
            userRoleBindingRepository,
            globalNamespaceMembershipService
        );
    }

    @Test
    void login_whenLdapDisabled_throwsServiceUnavailable() {
        given(ldapProperties.isEnabled()).willReturn(false);

        assertThatThrownBy(() -> service.login("alice", "secret"))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void login_whenUsernameNull_throwsUnauthorized() {
        given(ldapProperties.isEnabled()).willReturn(true);

        assertThatThrownBy(() -> service.login(null, "secret"))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  "})
    void login_whenUsernameBlank_throwsUnauthorized(String username) {
        given(ldapProperties.isEnabled()).willReturn(true);

        assertThatThrownBy(() -> service.login(username, "secret"))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void login_whenPasswordNull_throwsUnauthorized() {
        given(ldapProperties.isEnabled()).willReturn(true);

        assertThatThrownBy(() -> service.login("alice", null))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void login_whenPasswordEmpty_throwsUnauthorized() {
        given(ldapProperties.isEnabled()).willReturn(true);

        assertThatThrownBy(() -> service.login("alice", ""))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  "})
    void login_whenPasswordBlankOrEmpty_throwsUnauthorized(String password) {
        given(ldapProperties.isEnabled()).willReturn(true);

        assertThatThrownBy(() -> service.login("alice", password))
            .isInstanceOf(AuthFlowException.class)
            .extracting(e -> ((AuthFlowException) e).getStatus())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
