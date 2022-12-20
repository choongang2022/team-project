<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
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
<link rel="stylesheet" href="/css/stylesLec.css">

   <title>Professor Main</title>
<script type="text/javascript">
$(document).ready(function(){
	if($("#mainCheck").val() != "1") {
		location.href="/professor/professorMain";  
	}
});
/* $("#noticeTable").click(function(){
	
	
}); */


</script>
<style type="text/css">
a {
  text-decoration: none; /* 링크의 밑줄 제거 */
  color: inherit !important; /* 링크의 색상 제거 */
}
</style>
</head>

<body id="body-pd" style="background-color: rgb(214, 225, 237)">
	<!-- header main Logo -->
	<jsp:include page="mainLogo.jsp"></jsp:include>
	<input type="hidden" id="mainCheck" value="${mainCheck}">
	<!-- side nav bar -->
	<jsp:include page="sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->
	
	<!-- main content -->
	<div class="container-fluid w-100 h-100" style=" background-color: rgb(214, 225, 237)">
		<div class="row">

		<!-- content header -->
		<jsp:include page="headerInfo.jsp"></jsp:include>

		<main class="col-9 h-100 w-100">
			<div class="row m-5">

				<!-- card content -->  
				<div class="row mb-2 pe-0 ps-2" >
					<div class="col-md-6 me-4 rounded overflow-auto bg-white p-5" style="min-height: 400px;"> 
						<h5 class="fw-bold" style="display: inline;">강의목록</h5>
						<p class="font08" style="display: inline; float: right;">총 <b style="color: red; ">${lecCnt}</b>개의 수업이 있습니다</p><br>
						<hr class="mb-4">
						<input type="hidden" name="gubun" value="1">
						<c:forEach var="lec" items="${lecList}">
							<p class="mb-1" style="font-size: 1em;">(${lec.lecture.typeCode}${lec.lecture.id}) <b>${lec.lecture.name}</b> _${lec.lecture.grade}학년</p>
							<p class="mb-1 font08"  style="display: inline;">수강인원 : <b>${lec.memberCnt}</b>명</p>
							<div class="font08" style="display: inline; float: right;">
							<%-- 총 수업시간 : <b style="color: red">6</b>/${lec.maxCount}&nbsp; &#183; &nbsp; 휴강 : <b>${statusCnt1}</b> &nbsp; &#183; &nbsp; 보강 : <b>${statusCnt2}</b> --%>
								<button type="button" class="btn btn-secondary btn-sm  font09 ms-5"  style="display: inline; "
										onclick="location.href='lecAttendanceCheck?id=${lec.lecture.id}'">&nbsp; 전자출석부  &nbsp;</button>
								<button type="button" class="btn btn-primary btn-sm font09" style="display: inline;"
										onclick="location.href='reportList?id=${lec.lecture.id}'">&nbsp;&nbsp; 과제조회  &nbsp;&nbsp;</button>
							</div>
							<hr class="my-3">   
							<!-- <button type="button" class="btn btn-secondary btn-sm">강의평가조회</button> -->
							<!-- <hr> -->
						</c:forEach>
	                  </div>
                  <div class="col-md-5 rounded overflow-auto bg-white p-5" style="min-height: 400px;"> 
                     <div><div class="fw-bold h5" style="display: inline;">공지사항</div><a href="/professor/notice/noticeList"><i class="bi bi-plus ms-5 " style="display: inline; float: right;"></i></a></div>
						<hr class="mb-4">
                     <table class="Notice-table table table-hover mb-5 font09" id="noticeTable">
								<!-- <thead>
									<tr>
										<th>제목</th>
										<th>작성일자</th>
										<th>조회수</th>
									</tr>
								</thead> -->
								<tbody>
									<c:forEach items="${noticeList}" var="notice" varStatus="status">
										<%-- <c:set var="i" value='${i+1}'/>
										<c:set value='${member.memRole}' var="role" /> --%>
										<%-- <c:if
											test="${notice.noticeType eq role || notice.noticeType eq 'allContent'}"> --%>
											<tr>
												<%-- <td>${i}</td> --%>
												<td style="display: none;">${notice.noticeType}</td>
												<c:choose>
													<c:when test="${fn:length(notice.noticeTitle) gt 25}">
														<td>
															<a style="text-decoration: none; color: black;" href="/professor/noticeDetail?noticeNum=${notice.noticeNum}">${fn:substring(notice.noticeTitle, 0 , 25)}...</a>
														</td>
													</c:when>
													<c:otherwise>
														<td>
															<a href="/professor/noticeDetail?noticeNum=${notice.noticeNum}">${notice.noticeTitle }</a>
														</td>
													</c:otherwise>
												</c:choose>
												<c:choose>
													<c:when test="${notice.createdDate != null}">
														<c:set var="DateValue" value="${notice.createdDate}" />
														<td>${fn:substring(DateValue,0,10)}</td>
													</c:when>
													<c:when test="${notice.modifiedDate != null}">
														<c:set var="DateValue" value="${notice.modifiedDate}" />
														<td>${fn:substring(DateValue,0,10)}</td>
													</c:when>
												</c:choose>
												 <td>${notice.noticeHit}</td> 
											</tr>
									</c:forEach>
								</tbody>
						</table>
                  </div>
                 <%--  <div class="col-md-2  rounded  bg-light p-4" style="max-height: 300px;"> 
                     <button type="button" style="width: 30%;" class="btn btn-warning btn-sm my-2" 
                           onclick="location.href='/professor/calenderForm?userid=${userid}'">캘린더</button>
                  </div> --%>
               </div>
               
               <!-- footer -->
               <footer class="col-12 mt-5" style="height: 60px;">
               <jsp:include page="../footer.jsp"></jsp:include>
               </footer> 
            </div>
         </main>
		</div> 
	</div> 
   <!-- container div end -->
   
   <!-- NavBar 관련 IONICONS -->
   <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
   <!-- JS -->
   <script src="/js/main.js"></script>
</body>
</html>