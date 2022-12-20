<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	 <li><a href="${pageContext.request.contextPath}/manager/main" class="nav-link px-2 link-secondary">Home</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/approval" class="nav-link px-2 link-dark">결재관리</a></li>
            <li><a href="${pageContext.request.contextPath}/notice/noticeList" class="nav-link px-2 link-dark">게시판 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/attForm" class="nav-link px-2 link-dark">근태 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/deptForm" class="nav-link px-2 link-dark">부서 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/addressForm" class="nav-link px-2 link-dark">주소록 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/studentManage" class="nav-link px-2 link-dark">학사 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/mypage" class="nav-link px-2 link-dark">마이페이지</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/message/messageList" class="nav-link px-2 link-dark">쪽지함 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/registerTimeForm" class="nav-link px-2 link-dark">기간 관리</a></li>
            <li><a href="${pageContext.request.contextPath}/manager/bookList" class="nav-link px-2 link-dark">교재 관리</a></li>
</body>
</html>