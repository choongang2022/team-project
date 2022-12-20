package com.oracle.choongangGroup.ry.dao;

import java.util.List;

import com.oracle.choongangGroup.ry.model.BookCartVo;
import com.oracle.choongangGroup.ry.model.BookVo;
import com.oracle.choongangGroup.ry.model.OrderDetailVo;
import com.oracle.choongangGroup.ry.model.OrdersVo;

public interface ShopDao {

	List<BookVo> bookList(BookVo book);

	BookVo detailBookList(int bookId);

	List<BookVo> searchList(BookVo book);

	void addCart(BookCartVo cart);

	List<BookCartVo> bookCartList(String userId);

	void deleteCart(int cartNum);

	void orderInfo(OrdersVo order);

	void orderInfoDetail(OrderDetailVo orderDetail);

	void cartAllDelete(String userId);

	List<OrdersVo> orderList(OrdersVo order);

	List<OrdersVo> orderView(OrdersVo order);

	void updateState(OrdersVo order);

	List<OrdersVo> adminOrderList();

	List<OrdersVo> adminOrderView(OrdersVo order);

	void changeStock(BookVo book);

	void billUpdateState(OrdersVo order);

	List<OrdersVo> searchOrderList(OrdersVo order);

	int processTotal();


}
