<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
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


/* 삭제기능 구현 */
function likeDelete(index){
	var myuserid = $('#myuser'+index).val();
	var userid = $('#user'+index).val();
	
	console.log("myuserid -> " + myuserid);
	console.log("userid -> " + userid);
	if(confirm("삭제하시겠습니까?")){
		$.ajax({
					url 	: "phoneLikeDelete",
					data	: {"myUserid" : myuserid, "userid" : userid },
					dataType: 'text',
					success : function(data){
						$('#deleteLine'+index).remove();
					} 
		});
	}
	
}
	/*모달*/
	function fnModuleInfo(index){
		$('.modal-body').load("/professor/myLikeAddress?page="+index);
	}
</script>
    <title>즐겨찾기 주소록</title>
</head>

<!-- card content -->  
<div class="col-12 rounded-bottom overflow-auto  p-3" style="min-height: 550px;"> 
	<table class="table table-hover">
		<thead>
			<tr><th>이름</th><th>직위</th><th>부서</th><th>연락처</th><th>삭제</th></tr>
		</thead>
		<c:forEach var="like" items="${likeList}" varStatus="status">
			<tr id="deleteLine${status.index}">
				<td>
					<input type="text" name ="userid" id = "user${status.index}" value="${like.userid}" hidden="true">
					<input type="text" name ="myuserid" id = "myuser${status.index}" value="${like.myUserid}" hidden="true" >${like.member.name }
				</td>
				<c:if test="${like.member.dept.upDeptno == 100}">
					<td>교직원</td>							  		
				</c:if>
				<c:if test="${like.member.dept.upDeptno == 200}">
					<td>교수</td>							  		
				</c:if>
				<c:if test="${like.member.dept.upDeptno == null}">
					<td></td>							  		
				</c:if>
				<td>${like.member.dept.dname}</td>
				<td>${like.member.phone}</td>
				<td>
					<button type="button" class="btn btn-outline-danger" onclick="likeDelete(${status.index})">삭제</button>
				</td>
			</tr>	
		</c:forEach>
	<tbody>
	</tbody>
	</table>
<!-- Scrollable modal -->
<div class="modal fade" id="staticBackdrop" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="staticBackdropLabel">Modal title</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        ...
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary">Understood</button>
      </div>
    </div>
  </div>
</div>
                    	<!-- =============================================  -->
                    	<!-- ================= 페이징 작업 ==================  -->
                    	<!-- =============================================  -->
                    <nav aria-label="...">
					  <ul class="pagination" style="margin-left: 117px;">
					  
					    <li class="page-item">
					      <c:if test="${page > 0}">
						      <a class="page-link" data-bs-target="#staticBackdrop" onclick="fnModuleInfo('${page-1}')">Previous</a>				      
					      </c:if>
					      <c:if test= "${page == 0 }">
					      	  <a class="page-link">Previous</a>
					      </c:if>
					    </li>					  
					
					  <c:forEach var="i" begin="1" end="${totalPage}">
					    <li id="page-item${i}" class="page-item" onclick="active(${i})">
					    <a class="page-link" data-bs-target="#staticBackdrop"  onclick="fnModuleInfo('${i-1}')" >${i }</a></li>
					  </c:forEach>
					    <li class="page-item">
					    	<c:if test="${page < totalPage-1}">
						      <a class="page-link" data-bs-target="#staticBackdrop" onclick="fnModuleInfo('${page+1}')">Next</a>
					    	</c:if>
					      	<c:if test= "${page > totalPage-2}">
						      <a class="page-link">Next</a>
					      	</c:if>
					    </li>
					  </ul>
					</nav>
					</div>
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<script src="/js/main.js"></script>
</body>
</html>