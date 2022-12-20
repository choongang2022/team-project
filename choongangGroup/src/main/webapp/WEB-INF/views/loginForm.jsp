<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>

<!-- bootStrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- RSA JS -->
<script src="/js/jsbn.js" type="text/javascript"></script>
<script src="/js/rsa.js" type="text/javascript"></script>
<script src="/js/prng4.js" type="text/javascript"></script>
<script src="/js/rng.js" type="text/javascript"></script>
<!-- This Page JS -->
<script src="/js/loginForm.js" type="text/javascript"></script>
<style type="text/css">
	html, body {
		height: 100%;
	}
	body {
		background-color: rgb(214, 225, 237);
	}
	.container {
		max-width: 420px;
	}
</style>
</head>
<body>
	<main class="container position-absolute top-50 start-50 translate-middle form-signin w-100 m-auto">
	    <!-- main logo image -->
	    <img class="img img-fluid mb-5" src="/images/logo1.png" alt="logo1">
	
	    <div class="form-floating">
	    	<input type="text" class="form-control bg-light mb-1" id="username" placeholder="아이디를 입력하세요">
	    	<label for="floatingInput">아이디</label>
	    </div>
	    <div class="form-floating">
	    	<input type="password" class="form-control bg-light mb-3" id="password" placeholder="비밀번호를 입력하세요">
	    	<label for="floatingPassword">비밀번호</label>
	    </div>
		<!-- remember-me -->
	    <div class="checkbox mb-3">
	    	<label style="font-size: small;">
	    		<input type="checkbox" id="keepLogin" value="keepLogin"> 로그인 상태 유지
	    	</label>
	    </div>
	    <!-- errMsg -->
	    <div class="h6 mb-3 fw-normal" id="errMsg"></div>
		<!-- login button -->
	    <a href="/mainLogin" onclick="validateEncryptForm(); return false;"><button class="w-100 btn btn-lg btn-primary mb-3" type="button">로그인</button></a>
	    <div class="d-flex justify-content-center" style="font-size: small;">
		    <div class="d-flex justify-content-between">
		    	<a class="text-decoration-none text-muted" style="padding-left: 30px;" href="/anonymous/findIdForm">아이디 찾기</a>
		    	<div class="text-muted mx-3 pb-3">|</div>
		    	<a class="text-decoration-none text-muted" href="/anonymous/requestResetPwForm">비밀번호 찾기</a>
		    </div>
	    </div>
	    <p class="mt-3 mb-3 text-muted text-center" style="font-size: small;">&copy; 서울 마포구 신촌로 176<br>
										Copyright2022.Choongang University.All Rights Reserved</p>
	</main>

	<input type="hidden" id="rsaPulbicKeyModulus" value="${publicKeyModulus}">
	<input type="hidden" id="rsaPulbicKeyExponent" value="${publicKeyExponent}">
</body>
</html>