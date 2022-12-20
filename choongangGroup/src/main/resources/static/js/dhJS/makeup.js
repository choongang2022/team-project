	//페이지 로드 완료되면 실행될 function
	document.addEventListener("DOMContentLoaded", function(){
		showOrdersList();
		setMinDate();
	});
	
	// 과제 list 요청 function(ajax)
	function showOrdersList() {
		var selLec = document.getElementById("selLec");
		var ajaxAppend = document.getElementById("ajaxAppend");
		selLecValue = selLec.options[selLec.selectedIndex].value;
		// 강의날짜 list 요청
		$.ajax({
			type: "POST",
			url: "/professor/getOrderList",
			data: { // 서버에 보낼 data
				id : selLecValue
				},
			dataType: 'json', // 서버로부터 받을 data 의 형식
			success: function(data) {
					console.log(data);
					// append 전 요소 내용 비우기
					ajaxAppend.textContent = "";
					// 강의의 날짜 list 정보 출력
					$.each(data, function(index, item) {
						// 출력 append str
						var appStr = 
									 '<tr onclick="showOrderDetail('+ index +')">'+
									 '<td scope="col" style="width: 16%">' + item.lec_date + 
									 '<input type="hidden" name="lec_orders_id" id="lec_orders_id' + index + '" value="' + item.lec_orders_id + '">'+ 
									 '</td>'+
									 '<td scope="col" style="width: 14%">' + item.lec_day + '</td>'+
									 '<td scope="col" style="width: 14%">' + item.lec_time + '</td>'; 
						// 신청한 적이 없는 경우 와 신청한 적이 있는 경우
						if(!item.lec_order_status || item.lec_order_status == "정상강의") {
							appStr += '<td scope="col" style="width: 14%">' + '정상강의' + '</td>'+
									  '<td scope="col" style="width: 14%">' + '-' + '</td>'+
									  '<td scope="col" style="width: 14%">' + '-' + '</td>'+
									  '<td scope="col" style="width: 14%">' + '-' + '</td>';
							
						} else {
							appStr += '<td scope="col" style="width: 14%">' + item.lec_order_status + '</td>'+
									  '<td scope="col" style="width: 14%">' + item.lec_order_date + '</td>'+
									  '<td scope="col" style="width: 14%">' + item.lec_order_time + '</td>'+
									  '<td scope="col" style="width: 14%">' + item.lec_order_building + ' ' + item.lec_order_room + '</td>';
						}
						appStr += '</tr>';
						$("#ajaxAppend").append(appStr);
					});
			},
			error: function() {
				alert('error');
			}
		});
	}

	// 휴/보강 내역 detail ajax
	function showOrderDetail(index) {
		const id = $("input#lec_orders_id" + index).val();
		
		$.ajax({
			type: "POST",
			url: "/professor/showOrderDetail",
			dataType: "json",
			data: {
				lecOrdersId: id
			},
			success: function(data) {
				$("#selectedLec").   val("선택된 강의 날짜 : " + data.lec_date);
				$("#detailId").      val(data.lec_orders_id);
				$("#reason").        val(data.lec_order_reason);
				$("#status").        val(data.lec_order_status);
				$("#lec_order_date").val(data.lec_order_date);
				$("#lecTime1").      val(data.lec_order_time);
				$("#lecHour1").      val(data.lec_order_hour);
				$("#lec_building").  val(data.lec_order_building);
				$("#lec_room").      val(data.lec_order_room);
			},
			error: function(e) {
				alert(e);
			}
		});
	}
	
	// 휴/보강 detail 정보 입력
	// lec_order_status (정상강의, 임시저장, 승인대기, 승인, 승인거부) : String(-2, -1, 0, 1, 2)
	// tempStatus (임시저장, 승인요청 , 요청취소) : (0, 1, -1)
	function updateOrders(tempStatus) {
		//강의 미선택 check
		if($("#status").val() == "강의미선택") {
			alert("강의를 선택해주세요");
			return;
		//미입력 값 여부 check
		} else if(!$("#reason").val()  
			   || !$("#lec_order_date").val()  
			   || !$("#lecTime1").val() 
			   || !$("#lecHour1").val()  
			   || !$("#lec_building").val() 
			   || !$("#lec_room").val()
			     ) {
			alert("모든 정보를 입력해주세요");
			return;
		//check 통과한 경우 update실행
		} else {
			var ordersDto = new Object();
			// tempStatus 임시저장 0 , 승인요청 1 구분
			ordersDto.lec_orders_id      = $("#detailId").val();
			ordersDto.lec_order_reason   = $("#reason").val();
			if(tempStatus == 0) {
				ordersDto.lec_order_status   = "-1";
			} else if(tempStatus == 1) {
				ordersDto.lec_order_status   = "0";
			}
			ordersDto.lec_order_date     = $("#lec_order_date").val();
			ordersDto.lec_order_time     = $("#lecTime1").val();
			ordersDto.lec_order_hour     = $("#lecHour1").val();
			ordersDto.lec_order_building = $("#lec_building").val();
			ordersDto.lec_order_room     = $("#lec_room").val();
			
			console.log(ordersDto);
			$.ajax({
				type: "POST",
				url: "/professor/updateOrders",
				data: JSON.stringify(ordersDto),
				contentType: "application/json",
				traditional: true,
				success: function(data) {
					if(data > 0) {
						alert("입력성공");
						$("#status").val("0");
						showOrdersList();
						// 임시저장 경우
						if(tempStatus == 0) {
							$("#status").val("임시저장");
						// 승인요청 경우
						} else {
							$("#status").val("승인요청");
						}
					} else {
						alert("입력실패");
					}
				},
				error: function() {
					alert("서버에러");
				}
			});
		}
		
	}
	
	function cancleOrders() {
		//강의 미선택 check
		if($("#status").val() == "강의미선택") {
			alert("강의를 선택해주세요");
			return;
		}
		var ordersDto = new Object();
		ordersDto.lec_orders_id      = $("#detailId").val();
		ordersDto.lec_order_reason   = "";
		ordersDto.lec_order_status   = "-2";
		ordersDto.lec_order_date     = "";
		ordersDto.lec_order_time     = "";
		ordersDto.lec_order_hour     = "";
		ordersDto.lec_order_building = "";
		ordersDto.lec_order_room     = "";
		
		console.log(ordersDto);
		$.ajax({
			type: "POST",
			url: "/professor/updateOrders",
			data: JSON.stringify(ordersDto),
			contentType: "application/json",
			traditional: true,
			success: function(data) {
				if(data > 0) {
					alert("입력성공");
					$("#status").val("0");
					showOrdersList();
					$("#reason").        val("");
					$("#status").        val("정상강의");
					$("#lec_order_date").val("");
					$("#lecTime1").      val("");
					$("#lecHour1").      val("");
					$("#lec_building").  val("");
					$("#lec_room").      val("");
				} else {
					alert("입력실패");
				}
			},
			error: function() {
				alert("서버에러");
			}
		});
	}
	function setMinDate() {
		var today = new Date().toISOString().substring(0, 10);
		$("#lec_order_date").attr("min", today);
	}