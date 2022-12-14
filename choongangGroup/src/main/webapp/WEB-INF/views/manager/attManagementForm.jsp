<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ include file="header.jsp"%>
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
    <style> @import url('https://fonts.googleapis.com/css2?family=Crimson+Pro:wght@300&family=Old+Standard+TT:ital@0;1&family=Unbounded:wght@300&display=swap'); </style>
    <style type="text/css">
    	.total{
    		marin-top : 10px;
    		color : #6699FF;
    		font-size : 27px;
    		font-weight: 600;
    		font-family: 'Crimson Pro', serif;
    		
    		
    	}
    </style>
</head>
<script  src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript">

	/* 주차 Click */
	var index = 0;
	function weekWorkClick(vWeek){
	//	var user= $('#user'+vIndex).val();
	$('.weekclk').not('#weekWork'+index).text("");
	/* location.href="${pageContext.request.contextPath}/attForm?page="+vWeek; */
	vindex = vWeek+1;
	console.info(index);
 		$.ajax({
 			type: 'POST',
			url : '/attClk',
			data : {page : vWeek},
			dataType: 'json',
			success : function(data){
				console.log("성공");
				var str = "<table class='table table-hover'>"
        				+"<thead class='table-dark'><tr><th>일자</th><th>업무시작</th><th>업무종료</th><th>총근무시간</th>"
        				+"</thead>"
        				+"<tbody>";
			 	$.each(data,function(index,item){
		            	str +=	"<tr>"
		            			+"<td>"+item.workDate+"</td>"
		            			+"<td>"+item.attOnTime+"</td>"
		            			+"<td>"+item.attOffTime+"</td>"
		            			+"<td>"+item.totalTime+"</td>"
		            			+"</tr>";
				});
				str +="</tbody></table>";
			 	$('#weekWork'+vindex).append(str); 
			}
		}); 
	}
	
	
</script>



<body class="" id="body-pd" onload="printClock()">
    <!-- header -->
    <!-- <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <a class="navbar-brand">
            <button class="btn ms-2" type="button">
                <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
            </button>
        </a>
    </nav> -->
    <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
          <a href="/" class="navbar-brand">
            <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
          </a>
    
          <ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
  			<jsp:include page="navHeader.jsp"></jsp:include>
          </ul>
        </header>
    </nav>
    <!-- /header -->
    <!-- side nav bar -->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                    <a href="#" class="nav__logo"></a>
                </div>
                    <div href="#" class="nav__link collapses">
     				<ion-icon name="pie-chart-outline" class="nav__icon"></ion-icon>
                        <span class="nav_name">근태관리</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 180px;">
                            <a href="${pageContext.request.contextPath}/manager/attForm" class="collapse__sublink">나의 근태관리</a><br>
                            <a href="${pageContext.request.contextPath}/manager/attDeptMemberForm" class="collapse__sublink">부서별 근태관리</a>
                            <a href="${pageContext.request.contextPath}/manager/attAllMemberForm" class="collapse__sublink">사원별 근태관리</a>
                        </ul>
                    </div>
                <a href="/logout" class="nav__link">
                    <ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
                    <span class="nav_name">Log out</span>
                </a>
                </div>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->
    <!-- main content -->
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
        <div class="row">
        
            
            
            <!-- content header -->
            <jsp:include page="contentHeader.jsp"></jsp:include>
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>근태관리<i class="bi bi-chevron-right"></i>내 근태관리 
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                    	<div>내 근태현황</div><hr>
                    	<div class = "row">
                    		<div>
		                    	<div class="row">
		                    		<div class="col border border-2 p-3 mb-2  rounded-start border-secondary" style="text-align: center;font-weight: 700;">
		                    			이번 주 누적 근무시간<br>
		                    			<span class = "total">
		                    			${weekSum }
		                    			</span>
		                    		</div>
		                    		<div class="col border border-2 p-3 mb-2  rounded-start border-secondary" style="text-align: center;font-weight: 700;">
		                    			이번 주 초과 근무시간<br>
		                    			<span class = "total">
		                    			${weekOver }
		                    			</span>
		                    		</div>
		                    		<div class="col border border-2 p-3 mb-2 rounded-start border-secondary" style="text-align: center;font-weight: 700; ">
		                    			이번달 누적근무시간<br>
		                    			<span class = "total">
		                    			${monthTotalTime }
		                    			</span>
		                    		</div>
		                    		<div class="col border border-2 p-3 mb-2 rounded-start border-secondary" style="text-align: center;font-weight: 700; ">
		                    			이번 달 초과 근무시간<br>
		                    			<span class = "total">
		                    			${monthOver }
		                    			</span>
		                    		</div>
		                    	</div>
		                    	<div class="row">
		                    		<div class="col border border-2 p-3 mb-2 rounded-start border-secondary" style="text-align: center;font-weight: 700; ">
		                    			지난달 근무시간<br>
		                    			<span class = "total">
		                    			${lastMonthTotal }
		                    			</span>
		                    		</div>
		                    		<div class="col border border-2 p-3 mb-2 rounded-start border-secondary" style="text-align: center;font-weight: 700; ">
		                    			지난달 초과근무시간<br>
		                    			<span class = "total">
		                    			${lastMonthOver}
		                    			</span>
		                    		</div>
		                    		<div class="col border border-2 p-3 mb-2 rounded-start border-secondary" style="text-align: center;font-weight: 700;">
		                    			남은 연차<br>
		                    			<span class = "total">
		                    			${vacation}
		                    			</span>
		                    		</div>
		                    	</div>
                    		</div>
                    	</div>
                    	<div id="weekWorkClk1" onclick="weekWorkClick(0)">1주차</div><hr>
                    		<div class="weekclk" id = "weekWork1">
	                    		<table class="table table-hover">
	                    			<thead class="table-dark"><tr><th>일자</th><th>업무시작</th><th>업무종료</th><th>총근무시간</th>
	                    				</thead>
                    					<c:forEach var="attList" items="${attList }">
	                    				<tbody>
	                    					<tr>
	                    						<td>${attList.workDate }</td>
	                    						<td>${attList.attOnTime }</td>
	                    						<td>${attList.attOffTime }</td>
	                    						<td>${attList.totalTime }</td>
	                    					</tr>
	                    				</tbody>			
                    					</c:forEach>
	                    		</table>
                    		</div>
                    	<div id="weekWorkClk2" onclick="weekWorkClick(1)">2주차</div><hr>
                    		<div  class="weekclk" id = "weekWork2"></div>
                    	<div id="weekWorkClk3" onclick="weekWorkClick(2)">3주차</div><hr>
                    		<div  class="weekclk" id = "weekWork3"></div>
                    	<div id="weekWorkClk4" onclick="weekWorkClick(3)">4주차</div><hr>
                    		<div  class="weekclk" id = "weekWork4"></div>
                    	<div id="weekWorkClk5" onclick="weekWorkClick(4)">5주차</div><hr>
                    		<div  class="weekclk" id = "weekWork5"></div>
                    	
                    	
                    </div>
                </div>
        </div>
        <jsp:include page="../footer.jsp"></jsp:include>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>