<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
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
	<link rel="stylesheet" href="/css/stylesLec.css">
	<link rel="stylesheet" href="/css/styles.css">
	<script  src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript">

	/* 현재 페이지 표시하기 */
	const urlParams = new URL(location.href).searchParams;
	var page = parseInt(urlParams.get('page'));
	var pageResult = page + 1; 
	console.log(pageResult);
	$(document).ready(function(){
		$('#page-item'+pageResult).addClass(' active');		
	})


	/* 즐겨찾기 추가기능 */
	function phoneLikeSave(vIndex){
		var user= $('#user'+vIndex).val();
		console.log(user);
		$.ajax({
			url 	: 'phoneLikeSave',
			data	: {"userid" : user},
			dataType: 'text',
			success : function(data){
				console.log("성공");
				$('#msg').text(data);
				 
			}
		});
	}
	/*모달*/
 	function fnModuleInfo(index){
		console.log("성공");
		if(index == undefined || index == "undefined"){
			index = 0;
		}
		console.log(index);
		$('.modal-body').load("/professor/myLikeAddress?page="+index);
	}
	
</script>
</head>

<body id="body-pd"  style="background-color: rgb(214, 225, 237)">
	<jsp:include page="shortHeadrInfo.jsp"></jsp:include>
	
	<!-- side nav bar -->
	<jsp:include page="sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->

	<!------- main content ------------>
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
		<div class="row">

			<!------------- card header  컨텐츠 폼------------->
			<main class="col-9 h-100 w-100">
				
				<div class="row m-5">
					<!------------- 컨텐츠 경로 ------------->
					<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>주소록
						</div>
						
                    <!-- Scrollable modal -->
					<div class="modal fade" id="staticBackdrop" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
					  <div class="modal-dialog">
					    <div class="modal-content">
					      <div class="modal-header">
					        <h5 class="modal-title" id="staticBackdropLabel">즐겨찾기 주소록</h5>
					        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
					      </div>
					      <div class="modal-body">
					        
					      </div>
					      <div class="modal-footer">
					        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
					      </div>
					    </div>
					  </div>
					</div>
                    
					<!----- card content 내용 ------>
					<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;"> 
						<div class="mb-5">
							<button class="btn btn-danger font09"  data-bs-toggle="modal" data-bs-target="#staticBackdrop" onclick="fnModuleInfo(0)"
	                        	style=" float:left; display: inline;">&nbsp;&nbsp;내 즐겨찾기&nbsp;&nbsp;
	                       	</button>
	                       	<!-- 오류 메세지 출력 -->
		                    <span class="ms-5 font09 text-danger" id="msg" style="font-style: italic;">
							</span>
							<form action="searchAddress" >
			                    <div class="input-group mb-3" style="width: 350px; text-align: center; float: right;" >
									<input  type = "text"  name = "search" class="form-control" placeholder="이름을 검색하세요" aria-describedby="button-addon2">
									<button class="btn btn-outline-primary" type="submit" id="button-addon2"><i class="bi bi-search"></i></button>
								</div>
							</form>
						</div>
                    	<table class="table table-hover px-5" style="text-align: center;">
                    		 <thead>
							    <tr><th>번호</th><th>이름</th><th>직위</th><th>부서</th><th>이메일</th><th>연락처</th><th style="width: 7%;">즐겨찾기</th></tr>
							  </thead>
							  	<c:forEach var="address" items="${addressList}" varStatus="status">
								  	<c:if test="${address.dept.upDeptno == 200 || address.dept.upDeptno == 100}">
									  	<tr  style="vertical-align: middle;">
									  		<td >${status.index+1 }</td>
										  		<td><input type="text" name ="userid" id = "user${status.index}" value="${address.userid}" hidden="true">
										  			${address.name }</td>
										  		<c:if test="${address.dept.upDeptno == 100}">
											  		<td>교수</td>							  		
										  		</c:if>
										  		<c:if test="${address.dept.upDeptno == 200}">
											  		<td>교직원</td>
											  	</c:if>
											 	<c:if test="${address.dept.upDeptno == null }">
											  		<td></td>
											  	</c:if>
									  		<td>${address.dept.dname}</td>
									  		<td>${address.email}</td>
									  		<td>${address.phone}</td>
									  		<td>
									  			<button type="button" class="btn btn-outline-danger" onclick="phoneLikeSave(${status.index})">+</button>
									  		</td>
									  	</tr>	
									  </c:if>
							  	</c:forEach>
							  <tbody>
							  </tbody>
                    	</table>
                    	
                    	
                    	<!--================================================  -->
                    					<!-- 검색버튼 구현 -->
                    	<!--================================================  -->
	                   <nav aria-label="...">
					  <ul class="mt-3 pagination justify-content-center" >
					  
					    <li class="page-item">
					      <c:if test="${page > 0}">
						      <a class="page-link" href="addressForm?page=${page-1}">Previous</a>				      
					      </c:if>
					      <c:if test= "${page == 0 }">
					      	  <a class="page-link">Previous</a>
					      </c:if>
					    </li>					  
					
					  <c:forEach var="i" begin="1" end="${totalPage}">
					    <li id="page-item${i}" class="page-item" onclick="active(${i})">
					    <a class="page-link" href="addressForm?page=${i-1 }" >${i }</a></li>
					  </c:forEach>
					    <li class="page-item">
					    	<c:if test="${page < totalPage-1}">
						      <a class="page-link" href="addressForm?page=${page+1}">Next</a>
					    	</c:if>
					      	<c:if test= "${page > totalPage-2}">
						      <a class="page-link">Next</a>
					      	</c:if>
					    </li>
					  </ul>
					</nav>
                    </div>
                    <!-- footer -->
         
                </div>
           </main>
		</div> 
	</div> <!-- container div end -->
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<script src="/js/main.js"></script>
</body>
</html>