<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
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
<link rel="stylesheet" href="/css/styles.css">

    <title>SideBar sub menus</title>
</head>
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript">
function submit(){
	alert("기간이 아닙니다");
	
}
</script>

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
                        <i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i class="bi bi-chevron-right"></i>수강신청 <i class="bi bi-chevron-right"></i>안내문
                    </div>
                    <!-- --------------------------본  문 ----------------------------->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                    	<!----------- 안내문 ------------->
                    	<div class="border border-2  rounded text-center col-7 h-50 " style="margin: 3% auto 0; ">
                    		
	                    	<p class="fs-1 fw-bold mt-3" >안내문</p>
							<hr>
							<p class="fs-5 lh-lg mt-4 pt-3 fw-bold"> 
								장바구니 기간 : &nbsp; ${likeTime.start } ~ ${likeTime.end }
								<c:if test="${likeResult eq 'likeWrong'}"><span style="color: red;">장바구니 기간이 아닙니다</span></c:if>
								<br>
								수강신청 기간 : &nbsp; ${applyTime.start } ~ ${applyTime.end }
								<c:if test="${applyResult eq 'applyWrong'}"><span style="color: red;">수강신청 기간이 아닙니다</span></c:if>
							</p>                   	
                    	</div>
                        
						
							<!-- 버튼 -->
							
							<div class="col text-center " style=" margin-top: 65px;" >
							
							
								
								<button type="button" value="장바구니" 
									<c:if test="${likeResult eq 'ok'}"> 
										onclick="location.href='likeMain?userid=${userid}'" 
									</c:if> 
									<c:if test="${likeResult ne 'ok'}">
										onclick="submit()"
									</c:if>
									class="btn btn-secondary btn-lg" style="width: 28%; height:60px; margin-right: 2%; background-color:rgb(39, 40, 70)" >장바구니</button>
								
								
								
								
								
								<button type="button" value="수강신청" 
									<c:if test="${applyResult eq 'ok'}"> 
										onclick="location.href='applySelect?userid=${userid}'" 
									</c:if>
									<c:if test="${applyResult ne 'ok'}">
										onclick="submit()"
									</c:if>
									class="btn btn-secondary btn-lg" style="width: 28%; height:60px; background-color:rgb(39, 40, 70)">수강신청</button>
								
						
							
							</div>			
						
                   		
                   		
                    </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        
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