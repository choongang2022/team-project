<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ include file="header.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
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
<!-- <script type="text/javascript">
$(function(){
var jsonData = JSON.parse('${category}');
console.log(jsonData);
var cate1Arr = new Array();
var cate1Obj = new Object();
// 1차 분류 셀렉트 박스에 삽입할 데이터 준비
for(var i = 0; i < jsonData.length; i++) {
	
	if(jsonData[i].tier == "1") {
		cate1Obj = new Object();  //초기화
		cate1Obj.cateCode = jsonData[i].cateCode;
		cate1Obj.cateName = jsonData[i].cateName;
		cate1Arr.push(cate1Obj);
	}
}
// 1차 분류 셀렉트 박스에 데이터 삽입
var cate1Select = $(".category1")
for(var i = 0; i < cate1Arr.length; i++) {
	cate1Select.append("<option value='" + cate1Arr[i].cateCode + "'>"
						+ cate1Arr[i].cateName + "</option>");
}
$(document).on("change", ".category1", function(){
	var cate2Arr = new Array();
	var cate2Obj = new Object();
	
	// 2차 분류 셀렉트 박스에 삽입할 데이터 준비
	for(var i = 0; i < jsonData.length; i++) {
		
		if(jsonData[i].tier == "2") {
			cate2Obj = new Object();  //초기화
			cate2Obj.cateCode = jsonData[i].cateCode;
			cate2Obj.cateName = jsonData[i].cateName;
			cate2Obj.cateParent = jsonData[i].cateParent;
			
			cate2Arr.push(cate2Obj);
		} 
	}
	
	var cate2Select = $(".category2");
	
	/*
	for(var i = 0; i < cate2Arr.length; i++) {
			cate2Select.append("<option value='" + cate2Arr[i].cateCode + "'>"
								+ cate2Arr[i].cateName + "</option>");
	}
	*/
	
	cate2Select.children().remove();
 
	$("option:selected", this).each(function(){
		
		var selectVal = $(this).val();		
				
		cate2Select.append("<option value='" + selectVal + "'>전체</option>");
		
		for(var i = 0; i < cate2Arr.length; i++) {
			if(selectVal == cate2Arr[i].cateParent) {
				cate2Select.append("<option value='" + cate2Arr[i].cateCode + "'>"
									+ cate2Arr[i].cateName + "</option>");
			}
		}		
	});
	
});
});	
</script> -->
<style type="text/css">
	#container_box table td { width:100px; }
	section#container { padding:20px 0; border-top:2px solid #eee; border-bottom:2px solid #eee; }
	section#container::after { content:""; display:block; clear:both; }
	aside { float:left; width:200px; }
	div#container_box { float:right; width:calc(100% - 200px - 20px); }
	aside { float : left; width 200px;}	
	aside ul li { text-align:center; margin-bottom:10px; }
	aside ul li a { display:block; width:100%; padding:10px 0;}
 	aside ul li a:hover { background:#eee; }
	.inputArea { margin:10px 0; }
	select { width:100px; }
	label { display:inline-block; width:70px; padding:5px; }
	label[for='bookInfo'] { display:block; }
	input { width:150px; }
	textarea#bookInfo { width:400px; height:180px; }
	table tbody td {}
</style>
</head>
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
                    <a href="/manager/main" class="nav__logo">교재관리</a>
                </div>
                <div class="nav__list">
                    <div href="${pageContext.request.contextPath}/manager/bookList" class="nav__link collapses">
						<!-- <ion-icon name="folder-outline" class="nav__icon"></ion-icon> -->
						<!-- <i class="bi bi-gear-fill nav__icon" name="folder-outline"></i> -->
						<i class="bi bi-book nav__icon" name="folder-outline"></i>
						<span class="nav_name">교재관리</span>

						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

						<ul class="collapse__menu" style="width: 200px;">
							<a href="/manager/bookList" class="collapse__sublink">교재 목록</i></a></br>
							<a href="/manager/bookInsert" class="collapse__sublink">교재 입력</i></a></br>
                            <a href="/manager/adminOrderList" class="collapse__sublink">주문 관리</i></a></br>
						</ul>
					</div>
                </div>
                <a href="/logout" class="nav__link">
                    <ion-icon name="log-out-outline" class="nav__icon"></ion-icon>
                    <span class="nav_name">Log out</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->
    <!-- main content -->
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
        <div class="row">
        
            
         	<jsp:include page="contentHeader.jsp"></jsp:include>
                    <!-- card header -->
                    <div class="col-9 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px; margin-left: 150px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>교재 관리<i class="bi bi-chevron-right"></i>교재 목록
                    </div>
                    <!-- card content -->  
                    <div class="col-9 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px; margin-left: 150px;"> 
						<div class="rounded overflow-auto bg-light p-4" style="min-height: 400px;"> 
						
								<h1>
								<div class="d-flex justify-content-end">
									<a href="/manager/bookList"><i class="bi bi-book" style="color: black; margin-right: 20px;"></i></a>
									<a href="/manager/bookInsert"><i class="bi bi-pencil" style="color: black; margin-right: 20px;"></i></a>
									<a href="/manager/adminOrderList"><i class="bi bi-receipt" style="color: black; margin-right: 20px;"></i></a>
								</div>
								</h1>
							<h2 style="text-align: center;  font-weight: bold;">교재 목록</h2>
										<form action="/manager/getSearch">
											<div class="search_input">
													<input type="text" name="keyword" aria-describedby="button-search"style="height: 31px;" placeholder="책 이름 OR 저자"<c:if test="${keyword ne null}"> value="${keyword}" </c:if>>
													<button class="btn search_btn" id="button-search"	type="submit">검색</button>
											</div>
										</form>
							<section id="container">
									<div class="search_wrap">
									</div>
									<table style="text-align: center;">
										 <colgroup>
									        <col width="6%"/>
									        <col width="10%"/>
									        <col width="20%"/>
									        <col width="14%"/>
									        <col width="20%"/>
									        <col width="10%"/>
									        <col width="10%"/>
									        <col width="10%"/>
									      </colgroup>
										<thead>
												<tr>
													<th>책 번호</th>
													<th>책 이미지</th>
													<th>책 이름</th>
													<th>저자</th>
													<th>카테고리</th>
													<th>가격</th>
													<th>재고</th>
													<th>등록날짜</th>
												</tr>
										</thead>
										<tbody>
											<c:forEach var="list" items="${list}">
											<tr>
												<td>
												<a href="/manager/detailBookList?bookId=${list.bookId }">${list.bookId }</a></td>
												<td  class="image">
												<a href="/manager/detailBookList?bookId=${list.bookId }">
												<img alt="" src="${list.bookThumbImg }" style="width: 200px; height: 150px; object-fit: contain;" >
												</a>
												</td>
												<!-- style="webkit-box-orient: vertical;  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; " -->
												<td class="title">${list.bookName }</td>
												<td class="author">${list.publisher }</td>
												<td class="author">${list.cateName }</td>
												<td class="sell_price"><fmt:formatNumber value="${list.bookPrice }" pattern="###,###,###"/> 원</td>
												<td class="sell_price">${list.bookStock } 권</td>
												<td class="author"><fmt:formatDate value="${list.regDate }" pattern="yyyy-MM-dd"/></td>
												</tr>
											</c:forEach>
										</tbody>
									</table>
							</section>
						</div>
					</div>
					<!-- 페이징 번호 설정 -->
							<nav aria-label="Page navigation example">
							  <ul class="pagination justify-content-center">
							  <c:if test="${page.startPage > page.pageBlock }">
							    <li class="page-item">
							      <a class="page-link" href="bookList?currentPage=${page.startPage - page.pageBlock}" aria-label="Previous">
							        <span aria-hidden="true">&laquo;</span>
							      </a>
							    </li>
							    </c:if>  
							    <c:forEach var="i" begin="${page.startPage}" end="${page.endPage}">
							    <li class="page-item">
								    <a class="page-link" href="bookList?currentPage=${i}">${i}</a>
							    </li>
							    </c:forEach>
							    <c:if test="${page.endPage < page.totalPage}">
							    <li class="page-item">
							      <a class="page-link" href="bookList?currentPage=${page.startPage + page.pageBlock}" aria-label="Next">
							        <span aria-hidden="true">&raquo;</span>
							      </a>
							    </li>
							    </c:if>
							  </ul>
							</nav>
					<!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						@2022 ChoongAng University. All Rights Reserved.
					</footer> 
				</div>
			</main>
		</div>
	</div>
	
<!-- NavBar 관련 IONICONS -->
<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
<!-- JS -->
<script src="/js/main.js"></script>
</body>
</html>
<%-- <section id="container">
	<aside>
		<%@include file="include/aside.jsp" %>
	</aside>
	<div id="container_box"> 
		<h2>교재 목록</h2>
				<div class="search_area">
                	<div class="search_wrap">
						<form action="/manager/getSearch">
							<div class="search_input">
									<input type="text" name="keyword" aria-describedby="button-search"style="height: 31px;"<c:if test="${keyword ne null}"> value="${keyword}" </c:if>>
									<button class="btn search_btn" id="button-search"	type="submit">검색</button>
							</div>
						</form>
					</div>
				</div>
			<div class="list_search_result">
			<table class="type_list">
				
				
			</table>
			</div>
			</div>
</section> --%>