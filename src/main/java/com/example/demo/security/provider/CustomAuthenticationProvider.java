package com.example.demo.security.provider;

import com.example.demo.security.common.FormWebAuthenticationDetails;
import com.example.demo.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     *
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     * (인증에 관련된) 검증을 위한 구현 메서드
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 파라미터 authentication : AuthenticationManager 클래스로부터 전달받은 인증 객체 (아이디, 패스워드 정보가 담겨있음)
        String userId = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(userId);

        if(!passwordEncoder.matches(password, accountContext.getAccount().getUserPw())) {
            throw new BadCredentialsException("인증에 실패하였습니다.");
        }

        // username, password 이외에 들어오는 추가적인 파라미터를 가져온다.
        // AuthenticationDetailsSource 와 WebAuthenticationDetails 를 커스터마이징함.
        // AuthenticationManager 에 들어오기 전에 위 두개 과정에서 세팅 과정을 거친다.
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    /**
     * 파라미터로 전달되는 authentication 클래스 타입과
     * CustomAuthenticationProvider 가 사용하는 토큰의 타입과 일치할 때
     * 해당 provider 인증 처리를 할 수 있도록 조건을 준다.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
