<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
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
<link rel="stylesheet" href="/css/styles.css">

    <title>SideBar sub menus</title>
</head>

<body class="" id="body-pd">
  
    <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
          <a href="/" class="navbar-brand">
            <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
          </a>
    
  
        </header>
    </nav>
    <!-- /header -->
   	<!----------------------- side nav bar ---------------------------------->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                 
                </div>
                <div class="nav__list">
                	<div href="#" class="nav__link collapses">
                        <i class="bi bi-person-rolodex"></i>
                        <span class="nav_name">학사관리</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/listEmp" class="collapse__sublink">학적정보 조회</a></li>
                            <li><a href="/student/lectureListForm" class="collapse__sublink">강의목록 조회</a></li>
                            
                            <li><a href="/student/timetable" class="collapse__sublink">시간표 조회</a></li>
                           

                        </ul>
                    </div>
                    

					<a href="/student/gradeList" class="nav__link">
	                    <i class="bi-mortarboard"></i>
	                    <span class="nav_name">&nbsp;성적 관리</span>
	                </a>
		

					<a href="/student/evaluationList" class="nav__link">
	                    <i class="bi-pencil"></i>
	                    <span class="nav_name">&nbsp;강의 평가</span>
	                </a>


					<a href="/student/applyIndex" class="nav__link">
	                    <i class="bi bi-box-arrow-up-right"></i>
	                    <span class="nav_name">&nbsp;수강 신청</span>
	                </a>
                    <div href="/student/shopList" class="nav__link collapses">
                        <i class="bi bi-book"></i>
                        <span class="nav_name">&nbsp;교재 구매</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/shopList" class="collapse__sublink">교재 목록</a></li>
                            <li><a href="/student/cartList" class="collapse__sublink">장바구니</a></li>
                            <li><a href="/student/orderList" class="collapse__sublink">주문 목록</a></li>
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
<jsp:include page="header.jsp"></jsp:include>
	<!-- main content -->
	<div class="row">
		
	
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
		
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i class="bi bi-chevron-right"></i>수강신청 <i class="bi bi-chevron-right"></i>장바구니
                    </div>
                    <!-------------------------본문---------------------------->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
  
                        <!-- 장바구니 메인 제목-->
                        <div class="mt-3 mb-3">                    
                       	  <span class="fs-2 fw-bold">수강신청 장바구니</span> 
                          <span class="fs-6 fw-bold text-danger">(장바구니 교과목은 반드시  실 수강신청 기간에 신청)</span>
                        </div> 
                        
                        
                        
                        <!-- 공지사항 -->
                        <div>
	                      	<div class=" float-start col-12">
								<div class="fw-bold fs-5 border rounded-top p-2" style="background-color:#EAEAEA; height: 45px;">&nbsp; <i class="bi bi-bell-fill" style="color: rgb(39, 40, 70);"></i> &nbsp;공지사항</div>
								<div class=" fs-6 fw-bold border p-4" style="height: 260px;">									
									<p> ※ 수강신청 장바구니 유의사항 안내</p>
									<p class="px-3"> 
									<i class="bi bi-1-square-fill"></i> &nbsp;장바구니 시행 기간 : &nbsp;<!-- 장바구니기간 --><br>				 
									<i class="bi bi-2-square-fill"></i> &nbsp;장바구니 신청 대상 : &nbsp;2022학년도 2학기 (년도,월기준으로 설정)<br>
									<i class="bi bi-3-square-fill"></i> &nbsp;장바구니 최대 학점 : &nbsp;21학점<br>
									<i class="bi bi-4-square-fill"></i> &nbsp;장바구니 주요 사항<br>
										<span class="px-3">가. &nbsp;수업시간 중복 불가</span><br>
										<span class="px-3">나. &nbsp;장바구니 인원 제한 없음(실제 수강신청 시 수강 인원 제한 있음)</span></p>									
	                      		</div> 
	                      	</div>
                      </div>
                        
                        <!-- 버튼 -->                                 
                        <div class="container text-center mt-5 float-start">
						<!--   <div class="row "> -->
						    <!-- <div class="col-3 border rounded fs-6 fw-bold pt-2" style="background-color: #EAEAEA">
						      	
						    </div> -->
					  		 <div >
						      	<button class="btn btn-dark fw-bold col-12" style="background-color:rgb(39, 40, 70);" onclick="location.href='likeForm?userid=${userid}&lecName='">수강신청 장바구니 담기</button>
						    </div>

						  </div>
						</div>
						
						
						<%-- <div class="container text-center mt-3 float-start mb-4">
						  <div class="row">
						   <div class="col-3 border rounded fs-6 fw-bold pt-2" style="background-color: #EAEAEA">
						      	장바구니 시간표 조회
						    </div>
						    <div class="col-1 ">
						      	<button class="btn btn-dark" style="background-color:rgb(39, 40, 70);" onclick="location.href='likeForm?userid=${userid}'">Click</button>
						    </div>
						    
						  </div>
						</div>
                      	  --%>
                      	<!-- //////////////////////////////////// -->
                      		 
                      	 
                    </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        footer
                    </footer>    
                </div>
            </main>
        </div>
    </div>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>