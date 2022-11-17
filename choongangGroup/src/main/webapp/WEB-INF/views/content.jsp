<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
	<title>Content</title>
	<!-- bottSTrap CSS only -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous"/>
	<!-- bootStrap Icons -->
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
	<!-- JavaScript Bundle with Popper -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
	<!-- jQuery -->
	<script src="http://code.jquery.com/jquery-latest.min.js"></script>
	<!-- font awesome -->
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
	<!-- CSS -->
	<link rel="stylesheet" href="/css/styles.css">
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<!-- JS -->
	<script src="/js/main.js"></script>

</head>

<body class="" id="body-pd">
	<nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
		<header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/" class="navbar-brand">
				<img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
			</a>

			<ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
				<li><a href="#" class="nav-link px-2 link-secondary">Home</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Features</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Pricing</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">FAQs</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">About</a></li>
			</ul>
		</header>
	</nav>
	
	<!-- side nav bar -->
	<div class="l-navbar" id="navbar">
		<nav class="navv">
			<div>
				<div class="nav__brand">
					<ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
				</div>
				<div class="nav__list">
					<a href="#" class="nav__link active">
						<div style="width: 20px; height: 20px;">
							<i class="bi bi-mortarboard nav__icon "></i>
						</div>
						<span class="nav_name">학사관리</span>
					</a>
					<a href="#" class="nav__link">
						<div style="width: 20px; height: 20px;">
							<i class="bi bi-file-earmark-text nav__icon "></i>
						</div>
						<span class="nav_name">결재</span>
					</a>
	
					<div href="#" class="nav__link collapses">
						<ion-icon name="folder-outline" class="nav__icon"></ion-icon>
						<span class="nav_name">Projects</span>
	
						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>
	
						<ul class="collapse__menu">
							<a href="#" class="collapse__sublink">Data</a>
							<a href="#" class="collapse__sublink">Group</a>
							<a href="#" class="collapse__sublink">Members</a>
						</ul>
					</div>
	
					<a href="#" class="nav__link">
						<ion-icon name="pie-chart-outline" class="nav__icon"></ion-icon>
						<span class="nav_name">Analytics</span>
					</a>
	
					<div href="#" class="nav__link collapses">
						<ion-icon name="people-outline" class="nav__icon"></ion-icon>
						<span class="nav_name">Team</span>
	
						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>
	
						<ul class="collapse__menu">
							<a href="#" class="collapse__sublink">Data</a>
							<a href="#" class="collapse__sublink">Group</a>
							<a href="#" class="collapse__sublink">Members</a>
						</ul>
					</div>
	
					<a href="#" class="nav__link">
						<ion-icon name="settings-outline" class="nav__icon"></ion-icon>
						<span class="nav_name">Settings</span>
					</a>
				</div>
  				<a href="#" class="nav__link">
					<ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
					<span class="nav_name">Log out</span>
				</a>
			</div>
		</nav>
	</div>
	<!-- /side nav bar -->

	<!------- main content ------------>
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
		<div class="row">

			<!-- content header -->
			<div class="col-12 p-4" style="height: 150px; background-color: rgb(95, 142, 241); vertical-align: middle;">
				<div class="d-flex flex-row" >
					<div class="text-white h4">안녕하세요. <b>김중앙</b>님!</div>
					<span class="border border-1 border-white border-bottom rounded-pill text-white px-2 pt-1 pb-0 ms-2 me-3" 
						  style="font-size: 12px; height: 24px;">교수</span>
					<i class="text-white bi-gear-fill mx-2" style="height: 18px;"></i>
				</div>
				<div class="d-flex text-white" style="font-size: 14px;">이공대학 컴퓨터공학과 | 정교수</div>
				<div class="d-flex flex-low text-white" style="font-size: 14px;">
					<i class="bi bi-envelope-fill me-3 ml-0 "></i>test123@naver.com
				</div>
			</div>

			<!------------- card header  컨텐츠 폼------------->
			<main class="col-9 h-100 w-100">
				<div class="row m-5">
					<!------------- 컨텐츠 경로 ------------->
					<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>교수서비스 <i class="bi bi-chevron-right"></i>학사관리 <i class="bi bi-chevron-right"></i>강의 시간표 조회
					</div>
					<!----- card content 내용 ------>-
					<div class="col-12 rounded-bottom overflow-auto bg-light p-5" style="min-height: 550px;">
						<h2>강의관리</h2>
						<p style="font-size: 12px;">총 <b style="color: red;">2</b>개의 수업이 있습니다</p>
						<hr>
						

					</div>
					
					<!-- footer -->
					<footer class="col-12" style="height: 60px; font-size: 12px;">
						@2022 ChoongAng University. All Rights Reserved.
					</footer>    
				</div>
			</main>
		</div>
	</div>

</body>
</html>