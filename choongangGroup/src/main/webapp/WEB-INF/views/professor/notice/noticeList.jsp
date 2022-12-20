<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
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

</head>

<body id="body-pd"  style="background-color: rgb(214, 225, 237)">
	<jsp:include page="../shortHeadrInfo.jsp"></jsp:include>
	
	<!-- side nav bar -->
	<jsp:include page="../sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->


	<!------- main content ------------>
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
		<div class="row">
		
			<!------------- card header  컨텐츠 폼------------->
			<main class="col-9 h-100 w-100">
				<div class="row m-5">
				
					<!------------- 컨텐츠 경로 ------------->
					<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>공지사항 </div>
						
						<!----- card content 내용 ------>
						<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;">
							<table class="Notice-table table table-striped mb-5 ">
								<thead>
									<tr style="text-align: center;">
										<th style="width: 7%;">번호</th>
										<th style="width: 35%;">제목</th>
										<th style="width: 30%;">내용</th>
										<th style="width: 16%;">작성일자</th>
										<th style="width: 7%;">조회수</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${noticeList}" var="notice" varStatus="status">
										<c:set var="i" value='${i+1}'/>
										<c:set value='${member.memRole}' var="role" />
										<%-- <c:if
											test="${notice.noticeType eq role || notice.noticeType eq 'allContent'}"> --%>
											<tr>
												<%-- <td>${status.index+1+(page * 10)}</td> --%>
												<td style="text-align: center;">${i}</td>
												<td style="display: none;">${notice.noticeType}</td>
												<c:choose>
													<c:when test="${fn:length(notice.noticeTitle) gt 25}">
														<td>
															<a href="/professor/noticeDetail?noticeNum=${notice.noticeNum}">${fn:substring(notice.noticeTitle, 0 , 25)}...</a>
														</td>
													</c:when>
													<c:otherwise>
														<td><a
															href="/professor/noticeDetail?noticeNum=${notice.noticeNum}">${notice.noticeTitle }</a></td>
													</c:otherwise>
												</c:choose>
												<c:choose>
													<c:when test="${fn:length(notice.noticeContent) gt 25}">
														<td>${fn:substring(notice.noticeContent, 0 , 25)}...</td>
													</c:when>
													<c:otherwise>
														<td>${notice.noticeContent}</td>
													</c:otherwise>
												</c:choose>
												<c:choose>
													<c:when test="${notice.createdDate != null}">
														<c:set var="DateValue" value="${notice.createdDate}" />
														<td style="text-align: center;">${fn:substring(DateValue,0,10)}</td>
													</c:when>
													<c:when test="${notice.modifiedDate != null}">
														<c:set var="DateValue" value="${notice.modifiedDate}" />
														<td style="text-align: center;">${fn:substring(DateValue,0,10)}</td>
													</c:when>
												</c:choose>
												<td style="text-align: center;">${notice.noticeHit}</td>
											</tr>
										<%-- </c:if> --%>
									</c:forEach>
								</tbody>
							</table>
							<form action="/professor/notice/search" method="GET"
								class="form-inline p-2 bd-highlight " role="search"
								style="display: block;">
								<input type="text" name="keyword" class="form-control" id=search
									placeholder="검색" style="width: 300px; float: left; border-top-right-radius: 0 !important; border-bottom-right-radius: 0 !important;">
								<button class="btn btn-primary bi bi-search" style="float: left; border-top-left-radius: 0 !important; border-bottom-left-radius: 0 !important;"></button>
							</form>
							<nav aria-label="...">
								<ul class="pagination" style="margin-left: 40%;">
			
									<li class="page-item"><c:if test="${page > 0}">
											<a class="page-link" href="/professor/notice/noticeList?page=${page-1}">Previous</a>
										</c:if> <c:if test="${page == 0 }">
											<a class="page-link">Previous</a>
										</c:if></li>
									<c:forEach var="i" begin="1" end="${noticeTotal}">
										<li id="page-item${i}" class="page-item" onclick="active(${i})">
											<a class="page-link" href="/notice/noticeList?page=${i-1 }">${i }</a>
										</li>
									</c:forEach>
									<li class="page-item"><c:if test="${page < noticeTotal-1}">
											<a class="page-link" href="/professor/notice/noticeList?page=${page+1}">Next</a>
										</c:if> <c:if test="${page > noticeTotal-2}">
											<a class="page-link">Next</a>
										</c:if></li>
								</ul>
							</nav>
						</div>
				
					 <!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						<jsp:include page="../../footer.jsp"></jsp:include>
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