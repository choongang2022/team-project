package com.oracle.choongangGroup.ry.service;

import java.util.List;

import com.oracle.choongangGroup.ry.model.BookCartVo;
import com.oracle.choongangGroup.ry.model.BookVo;
import com.oracle.choongangGroup.ry.model.OrderDetailVo;
import com.oracle.choongangGroup.ry.model.OrdersVo;

public interface ShopService {


	List<BookVo> bookList(BookVo book);

	BookVo bookDetailList(int bookId);

	List<BookVo> getSearchList(BookVo book);

	void addCart(BookCartVo cart);

	List<BookCartVo> cartList(String userId);

	void deleteCart(int cartNum);

	void orderInfo(OrdersVo order);

	void orderInfo_Details(OrderDetailVo orderDetail);

	void cartAllDelete(String userId);

	List<OrdersVo> orderList(OrdersVo order);

	List<OrdersVo> orderView(OrdersVo order);

	void updateState(OrdersVo order);

	List<OrdersVo> adminOrderList();

	List<OrdersVo> adminOrderView(OrdersVo order);

	void changeStock(BookVo book);

	void billUpdateState(OrdersVo order);

	List<OrdersVo> SearchOrderList(OrdersVo order);

	int processTotal();



}
