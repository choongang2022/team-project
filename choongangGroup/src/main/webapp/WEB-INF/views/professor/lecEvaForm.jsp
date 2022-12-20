<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt"  uri="http://java.sun.com/jsp/jstl/fmt"%>
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
<script type="text/javascript">
	$(document).ready(function(){
		var str = "";
		
		
		// 강의 이름 select Box
		$.ajax({
			url : '/professor/findProf',
			dataType : 'json',
			success  : function(data){
				$.each(data,function(index,item){
					str += "<option value='" + item.lecId + "'>" +'(' +item.typeCode + item.lecId+') '+ item.lecName + "</option>";
				});
				
				const urlParams = new URL(location.href).searchParams;
				var lecid = urlParams.get('lecId');
				$('#lecName').append(str);
				
				if (lecid != null){
					$("#lecName").val(lecid).prop("selected", true);
				}
			}
		});

		// 강의 이름이 변경되었을 때
		$('#lecName').on('change',function(){
			var optionName = $("#lecName").val();
			
			location.href = "/professor/EvaManagementForm?lecId=" + optionName;
		});
		
		
	});
</script>
<style type="text/css">
	#headFont{
		font-size : 18px;
		font-weight : 600;
		margin : 50px 0px 50px 0px;
	}
	.score{
    	font-size: 50px;
    	font-family: 'Crimson Pro', serif;
    	color : green;		
	}
	.koreafont{
		font-size: 22px;
		color : green;		
		font-family: 'Crimson Pro', serif;
	}
	.koreafont-1{
		font-size: 18px;
		color : gray;
		font-weight : 600;
		font-family: 'Crimson Pro', serif;
	}
	 .star {
    position: relative;
    font-size: 1.9rem;
    color: #aaa9a9;
  }
  
  .star span {
    width: 0;
    position: absolute; 
    left: 0;
    color: #fff58c;
    overflow: hidden;
    pointer-events: none;
    -webkit-text-fill-color: gold;
  }
  .review{
  	color : gray;
  	padding-left : 100px;
  	padding-bottom : 30px;
  }
  .bi-alexa{
  	padding-right : 20px;
  }
</style> 
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
						<i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의평가 </div>
					<!----- card content 내용 ------>
						<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;">
						
							<h2>강의평가</h2><hr>
							<div class="mb-4">
	                    		<div class = "col-1 m-2" style="line-height: 2.5;font-weight: 700;font-size: 17px; display: inline;">
	                    			강의 이름  
	                    		</div>
	                    		<div class = "col-2 m-2 " style=" display: inline;">
		                    		<select class="form-select" id = "lecName" aria-label="Default select" style=" display: inline;">
		                    		</select>
	                    		</div>
	                    	</div>
	                    	<div class = "row mb-4" >
		                    	<div class="col-1" id = "headFont">
		                    		만족도
		                    	</div>
	                    		<div class = "col-4 border-end border-2" style="text-align: center;">
	                    			<c:if test="${total.totalAvg eq 0 || total.totalAvg eq null}"><span class="score text-danger">0</span></c:if>
	                    			<c:if test="${total.totalAvg ne 0}"><span class="score text-danger">${total.totalAvg}</span></c:if><br>
	                    			<span class = "koreafont-1">평균만족도</span>
	                    		</div>
	                   			<div class = "col-4 border-end border-2" style="text-align: center;">
	                   				<c:if test="${total.evaCnt eq 0 || total.evaCnt eq null}">
	                    				<span class="score text-danger">${total.totalCnt} / 0</span>
	                    			</c:if>
	                    			<c:if test="${total.evaCnt ne 0 && total.evaCnt ne null }">
	                    				<span class="score text-danger">${total.totalCnt} / ${total.evaCnt}</span>
	                    			</c:if>
	                    			<span class = "koreafont text-danger">명</span><br>
	                    			<span class = "koreafont-1">수강인원 / 평가인원</span>
	                    		</div>
	                    		<%-- <div class = "col-2 border-end border-2" style="text-align: center;">
	                    			<span class="score">${total.evaCnt}</span><span class = "koreafont">명</span><br>
	                    			<span class = "koreafont-1">평가인원</span>
	                    		</div> --%>
	                    		<div class = "col-3" style="text-align: center;">
	                    			<span class="score text-danger">
	                    				<fmt:formatNumber value="${total.evaCnt/total.totalCnt }"  type="percent"></fmt:formatNumber>
	                    			</span><br>
	                    			<span class = "koreafont-1">평가참여율</span>
	                    		</div>
	                    	</div>
	                    	
	                    	<div class = "row mb-5">
		                    	<c:if test="${evaList.size()==0}">
		                    		<!-- <div class="col-3"></div> -->
		                    		<div class = "col-4  fw-bold">
		                    			수업내용
										<span class="star ms-1">
										  ★★★★★
										  <span style="width:0%">★★★★★</span>
										</span>
		                    			<span class="font08"> (0점)</span>
		                    		</div>
		                    		<div class = "col-4  fw-bold">
		                    			수업방법 
		                    			<span class="star ms-1">
										  ★★★★★
										  <span style="width:0%">★★★★★</span>
										</span>
		                    			<span class="font08"> (0점)</span>
		                    		</div>
		                    		<div class = "col-4  fw-bold">
		                    			수업유형
		                    			<span class="star ms-1">
										  ★★★★★
										  <span style="width:0%">★★★★★</span>
										</span>
		                    			<span class="font08"> (0점)</span>
		                    		</div>
		                    	</c:if>
		                   
		                    	<c:if test="${evaList.size()!=0}">
		                    		<!-- <div class="col-1"></div> -->
			                    	<c:forEach var="eva" begin="0" end="${evaList.size()-1}" items="${evaList }">
			                    	
			                    		<c:if test="${eva.bigCategory == 10}">
				                    		<div class = "col-4  fw-bold">
				                    			수업내용
												<span class="star ms-1">
												  ★★★★★
												  <span style="width:${eva.avg*18.8}%">★★★★★</span>
												</span><span class="font08"> (${eva.avg}점/5점)</span>
				                    		</div>
			                    		</c:if>
			                    		<c:if test="${eva.bigCategory == 20}">
				                    		<div class = "col-4  fw-bold">
				                    			수업방법  
				                    			<span class="star ms-1">
												  ★★★★★
												  <span style="width:${eva.avg*18.8}%">★★★★★</span>
												</span><span class="font08"> (${eva.avg}점/5점)</span>
				                    		</div>
			                    		</c:if>
			                    		<c:if test="${eva.bigCategory == 30}">
				                    		<div class = "col-4  fw-bold">
				                    			수업유형
				                    			<span class="star ms-1">
												  ★★★★★
												 <span style="width:${eva.avg*18.8}%">★★★★★</span>
												 </span><span class="font08"> (${eva.avg}점/5점)</span>
				                    		</div>
			                    		</c:if>
			                    	</c:forEach>
		                    	</c:if>
	                    	</div>
                    		<div class ="border-bottom border-3 mt-4 mb-3 pb-3" style ="font-weight: 700;">수강후기</div>
								<c:if test="${reviewList.size() != 0}">
	                    			<c:forEach var="review" items="${reviewList}">
		                    		<div class = "review">
	                    				<i class="bi bi-alexa"></i>${review.review}
	    	                		</div>
	                    			</c:forEach>
								</c:if>
                    	</div>
                    	
					
					<!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						<jsp:include page="../footer.jsp"></jsp:include>
					</footer> 
					<!-- </footer>  -->
				</div>
			</main>
		</div> 
	</div> <!-- container div end -->
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<script src="/js/main.js"></script>
</body>
</html>