# Spring Security 실전 프로젝트

* 강의 : [스프링 시큐리티 - Spring Boot 기반으로 개발하는 Spring Security (정수원)](https://www.inflearn.com/course/%EC%BD%94%EC%96%B4-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0/dashboard)
* 인프런 Spring- Security 강의를 들으면서 따라한 실전 프로젝트를 정리한 리포지토리 입니다.
* 프로젝트 진행하는 모든 소스 코드는 강사님의 [개인 github](https://github.com/onjsdnjs/corespringsecurity)에 올라가 있어 오픈소스로 판단하고 리포지토리에 정리 하였습니다. (강의 내용을 정리한 내용 및 실습 코드들은 private 리포지토리 형태로 저장하였음)

<br/>

## # 01. 실전 프로젝트 구성

1. 프로젝트 명 : core-spring-security
2. 프로젝트 기본 구성
   * 의존성 설정, 환경 설정, UI 화면 구성, 기본 CRUD 기능
   * 스프링 시큐리티 보안 기능을 점진적으로 구현 및 완성
3. Springboot, Spring MVC, Spring Data JPA
4. 프로그램 설치
   * DB - Postgresql Serverop

<br/>

* Controller 파일들 생성
* Config 파일 생성
* html View 파일들 생성

<br/>

<br/>

### # 02. 메뉴 권한 및 WebIgnore 설정

> js / css / image 파일 등 보안 필터를 적용할 필요가 없는 리소스를 설정

```java
@Override
public void configure(WebSecurity web) throws Exception {
    web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
}
```

<br/>

### # 04. Form 인증 – User 등록 / PasswordEncoder

* 비밀번호를 안전하게 암호화 하도록 제공
* Spring Security 5.0 이전에는 기본 PasswordEncoder 가 평문을 지원하는 NoOpPasswordEncoder

<br/>

#### 생성

```java
PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
```

* 여러 개의 PasswordEncoder 유형을 선언한 뒤, 상황에 맞게 선택해서 사용할 수 있도록 지원하는 Encoder.

<br/>

#### 암호화 포맷 : {id}encodedPassword

* 알고리즘 종류 : bcrypt, noop, pbkdf2, scrypt, sha256
* 기본 포맷은 Bcrypt : {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG

<br/>

#### 인터페이스

* encode(password)
  * 패스워드 암호화
* matches(rawPassword, encodedPassword)
  * 패스워드 비교

<br/>

<br/>

### # 05. Form 인증 – CustomUserDetailsService

> DB로부터 사용자를 직접 조회하고, 인증을 처리하도록!

![image-20210505133642574](./images/image-20210505133642574.png)

```java
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	Account account = userRepository.findByUsername(username);

    if (account == null) {
		throw new UsernameNotFoundException("No user found with username: " + username);	}
    
	// 권한
    ArrayList<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
    roles.add(new SimpleGrantedAuthority(account.getRole()));
	return new AccountContext(account, roles);
}
```

<br/>

<br/>

### # 06. Form 인증 – CustomAuthenticationProvider



![image-20210505153958846](./images/image-20210505153958846.png)

```java
public Authentication authenticate(Authentication auth) throws AuthenticationException {
	String loginId = auth.getName();
    String passwd = (String) auth.getCredentials();
    
    UserDetails userDetails = uerDetailsService.loadUserByUsername(loginId);

    if (userDetails == null || !passwordEncoder.matches(passwd, userDetails.getPassword())) {
		throw new BadCredentialsException("Invalid password");
	}

    return new UsernamePasswordAuthenticationToken(userDetails.getUser(), null, userDetails.getAuthorities());
}
```

<br/>

<br/>

### # 07. Form 인증 – Custom Login Form Page

> 사용자 구현 Login Page

<br/>

![image-20210506212139268](./images/image-20210506212139268.png)

```java
@Override
public void configure(HttpSecurity http) throws Exception {
    http.formLogin().loginPage("/customLogin")
}
```

<br/>

<br/>

### # 08. Form 인증 - 로그아웃 및 화면 보안 처리

* 로그아웃 방법
  * \<form> 태그를 사용해서 POST로 요청
  * \<a> 태크를 사용해서 GET 으로 요청 – SecurityContextLogoutHandler 활용

* 인증 여부에 따라 로그인/로그아웃 표현
  * \<li sec:authorize="isAnonymous()">\<a th:href="@{/login}">로그인\</a>\</li>
  * \<li sec:authorize="isAuthenticated()">\<a th:href="@{/logout}">로그아웃\</a>\</li>

```java
@GetMapping(value = "/logout")
public String logout(HttpServletRequest request, HttpServletResponse response) {
	Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	if (auth != null) {
		new SecurityContextLogoutHandler().logout(request, response, auth);
	}
	return "redirect:/login";
}
```

<br/>

<br/>

### # 08. Form 인증 – WebAuthenticationDetails AuthenticationDetailsSource

![image-20210507181925826](./images/image-20210507181925826.png)

* Authentication객체는 details라는 속성을 가지고 있다.
* 이 속성에 WebAuthenticationDetails라는 객체가 저장되어 있다.
* 이 객체는 request 라는 객체를 통해서 얻어온 추가적인 파라미터 값들을 저장하고 있다.

<br/>

#### WebAuthenticationDetails

> 사용자가 추가로 전달하는 파라미터들을 얻어서, 저장하는 역할

* 인증 과정 중 전달된 데이터를 저장
* Authentication의 details 속성에 저장

<br/>

#### AuthenticationDetailsSource

> WebAuthenticationDetails 객체를 생성

<br/>

<br/>

### # 09. Form 인증 – CustomAuthenticationSuccessHandler

> 인증에 성공 시 수행하는 SuccessHandler

<br/>

#### SecurityConfig

```java
@Override
public void configure(HttpSecurity http) throws Exception {
    http.formLogin().successHandler(CustomAuthenticationSuccessHandler())
}
```

<br/>

#### CustomAuthenticationSuccessHandler

```java
@Override
public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
	setDefaultTargetUrl("/");

	SavedRequest savedRequest = requestCache.getRequest(request, response);
    if (savedRequest != null) {
    	String targetUrl = savedRequest.getRedirectUrl();
        redirectStrategy.sendRedirect(request, response, targetUrl);
	} else {
    	redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
	}     
}
```

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

