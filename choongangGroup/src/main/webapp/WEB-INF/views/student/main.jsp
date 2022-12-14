<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- bottSTrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles2.css">
<link rel="stylesheet" href="/css/stylesLec.css">

	<title>Student Main</title>
</head>

<body id="body-pd">
	<!-- header -->
	<nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
		<header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/student/main" class="navbar-brand  ms-3">
				<img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"></svg>
			</a>

			<!-- <ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
				<li><a href="#" class="nav-link px-2 link-secondary">Home</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Features</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Pricing</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">FAQs</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">About</a></li>
			</ul> -->
		</header>
	</nav>
	
	<!-- side nav bar -->

	
	<!-- side nav bar -->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                   <!--  <a href="#" class="nav__logo">????????????</a> -->
                </div>
                <div class="nav__list">
                	<div href="#" class="nav__link collapses">
                        <i class="bi bi-person-rolodex"></i>
                        <span class="nav_name">????????????</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/listEmp" class="collapse__sublink">???????????? ??????</a></li>
                            <li><a href="/student/lectureListForm" class="collapse__sublink">???????????? ??????</a></li>
                            
                            <li><a href="/student/timetable" class="collapse__sublink">????????? ??????</a></li>
                           

                        </ul>
                    </div>
                    

					<a href="/student/gradeList" class="nav__link">
	                    <i class="bi-mortarboard"></i>
	                    <span class="nav_name">&nbsp;?????? ??????</span>
	                </a>
		

					<a href="/student/evaluationList" class="nav__link">
	                    <i class="bi-pencil"></i>
	                    <span class="nav_name">&nbsp;?????? ??????</span>
	                </a>


					<a href="/student/applyIndex" class="nav__link">
	                    <i class="bi bi-box-arrow-up-right"></i>
	                    <span class="nav_name">&nbsp;?????? ??????</span>
	                </a>
                    <div href="/student/shopList" class="nav__link collapses">
                        <i class="bi bi-book"></i>
                        <span class="nav_name">&nbsp;?????? ??????</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/shopList" class="collapse__sublink">?????? ??????</a></li>
                            <li><a href="/student/cartList" class="collapse__sublink">????????????</a></li>
                            <li><a href="/student/orderList" class="collapse__sublink">?????? ??????</a></li>
                        </ul>
                    </div>
                </div>
                <a href="/logout" class="nav__link">
                    <i class="bi-power"></i>
                    <span class="nav_name">&nbsp; Log out</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->

	<!-- main content -->
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
		<div class="row">
		
			<!-- content header -->
			<div class="col-12 px-5 py-4" style=" background-color: rgb(95, 142, 241)">
				<div class="d-flex flex-row mb-2 mt-2">
					<div>
						<span class="text-white h4">???????????????. <span class="fw-bold">${member.name}</span>???!</span>
					</div>
					<div class="border border-1 border-white rounded-pill text-white ms-2"  style="height: 25px;">
						<div class="font09 align-items-center">&nbsp; ??????  &nbsp;</div>
					</div>
					<div><i class="text-white bi-gear-fill mx-2">  </i></div>
				</div>
				<div class="row">

				<div>
					<span class="text-white font09">${member.major}???&nbsp; &nbsp; ${member.grade}&nbsp;?????? </span>
				</div>
				</div>
				<div class="d-flex flex-low mb-2">
					<div><i class="bi bi-envelope-fill text-white"></i></div>
					<div><span class="text-white ms-2 font09">${member.email}</span></div>
				</div>

			</div>

			<main class="col-9 h-100 w-100">
				<div class="row m-5">
				
					<!-- card content -->  
					<div class="row mb-2 pe-0 ps-2" >
						<div class="col-md-5 me-3 rounded overflow-auto bg-light p-4" style="min-height: 400px;"> 
							<h5 class="fw-bold"><i class="bi bi-pencil-square"></i>&nbsp;&nbsp;????????? ??????</h5><hr>
							<input type="hidden" name="gubun" value="1">
							
							<!-- ----------------------------------------------------------- -->
							<%-- <p class="font08">??? <b style="color: red">${i.index}</b>?????? ????????? ????????????</p><br> --%>
							
							
								<c:forEach var="lec" items="${list}" >
								<c:if test="${lec.lecture.day1 eq today or lec.lecture.day2 eq today }">
								
									<p style="font-size: 1.4em;">${lec.lecture.name}<b></b> </p>
										<p class="mb-1 font09">????????? : <b>${lec.lecture.building}${lec.lecture.room}</b></p>
										<c:if test="${lec.lecture.day1 eq today}">
											<div class="font09">?????? ?????? : <b style="color: red">${lec.lecture.time1}</b>??????&nbsp; &nbsp;-&nbsp; &nbsp; <b style="color: red">${lec.lecture.time1 + lec.lecture.hour1}</b> ??????
										</c:if>
										
										<c:if test="${lec.lecture.day2 eq today}">
											<div class="font09">?????? ?????? : <b style="color: red">${lec.lecture.time2}</b>/??????&nbsp; &nbsp;-&nbsp; &nbsp; <b style="color: red">${lec.lecture.time2 + lec.lecture.hour2}</b> ??????
										</c:if>
											
											
											&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<button type="button" class="btn btn-primary btn-sm font09"	
													onclick="location.href='lectureListForm'">&nbsp; ????????????  &nbsp;</button>
										</div>
										<hr class="my-4">	
							
								</c:if>
								</c:forEach> 
						</div>
						<!-- <div class="col-md-3 me-3 rounded overflow-auto bg-light p-4" style="min-height: 400px;"> 
							<h5><a href="/notice/noticeList">????????????</a></h5><hr>

						</div> -->
						<div class="col-md-6  rounded overflow-auto bg-light p-4" style="max-height: 300px;"> 
							<h5>?????????</h5><hr>
							<!--------------------------------- ????????? -------------------------------------->
							<div class="mt-1 timetable" >
								<table class="timetable" style="background-color: #F2F8F8 ; color: 	#003A9D" >								
												<thead >
												<tr >
													<th style="width: 6%; ">??????</th><th>???</th><th>???</th><th>???</th><th>???</th><th>???</th>											
												</tr>
												</thead>									
												<tbody>			
													
									<c:forEach var="j" begin="1" end="7">	
										<tr>
											<td style="width: 6%">${j }??????</td>	
											
											<c:forEach var="d" items="${day }">
															
												<c:forEach var="lec" items="${list }" >	
													<c:if test="${lec.lecture.day1 eq d and lec.lecture.time1 le j and lec.lecture.time1+lec.lecture.hour1 gt j}">
														<c:set var="day1" value="${lec.lecture.day1 }"></c:set> 
														<c:set var="name1" value="${lec.lecture.name }"></c:set>
														<c:set var="time1" value="${lec.lecture.time1 }"></c:set>
														<c:set var="hour1" value="${lec.lecture.hour1 }"></c:set>
													</c:if>	
													
													
													
													<c:if test="${lec.lecture.day2 eq d and lec.lecture.time2 le j and lec.lecture.time2+lec.lecture.hour2 gt j}">
														<c:set var="day2" value="${lec.lecture.day2 }"></c:set> 
														<c:set var="name2" value="${lec.lecture.name }"></c:set>
														<c:set var="time2" value="${lec.lecture.time2 }"></c:set>
														<c:set var="hour2" value="${lec.lecture.hour2 }"></c:set>
													</c:if>															
												</c:forEach>
												
												<c:choose>
													<c:when test="${day1 eq d and time1+hour1 gt j}"> 
													 	<td style="background-color: #6799FF; color: white;">${name1 }</td>
													</c:when>
													<c:when test="${day2 eq d and time2+hour2 gt j}"> 
													 	<td style="background-color: #B2CCFF; color: white">${name2 }</td>
													</c:when>
													<c:otherwise>
														<td></td>
													</c:otherwise>
												</c:choose>
											</c:forEach>	
											</tr>
										</c:forEach>	
													 
									</tbody>																	
								</table> 
								
								
							</div>	
								
									

						</div>
					</div>
					
					<!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						@2022 ChoongAng University. All Rights Reserved.
					</footer> 
				</div>
			</main>
		</div>
	</div>
	
<!-- NavBar ?????? IONICONS -->
<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
<!-- JS -->
<script src="/js/main.js"></script>
</body>
</html>