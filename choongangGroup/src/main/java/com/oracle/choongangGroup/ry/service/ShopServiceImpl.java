package com.oracle.choongangGroup.ry.service;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.ry.dao.ShopDao;
import com.oracle.choongangGroup.ry.model.BookCartVo;
import com.oracle.choongangGroup.ry.model.BookVo;
import com.oracle.choongangGroup.ry.model.OrderDetailVo;
import com.oracle.choongangGroup.ry.model.OrdersVo;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class ShopServiceImpl implements ShopService {
	
	
	private final ShopDao sd;

	@Override
	public List<BookVo> bookList(BookVo book) {
		List<BookVo> bookList = sd.bookList(book);
		return bookList;
	}

	@Override
	public BookVo bookDetailList(int bookId) {
		System.out.println("bookDetailList start........");
		BookVo book = sd.detailBookList(bookId);
		return book;
	}

	@Override
	public List<BookVo> getSearchList(BookVo book) {
		
		
		return sd.searchList(book);
	}

	@Override
	public void addCart(BookCartVo cart) {
		sd.addCart(cart);
		
	}

	@Override
	public List<BookCartVo> cartList(String userId) {
		List<BookCartVo> cartList = sd.bookCartList(userId);
		return cartList;
	}

	@Override
	public void deleteCart(int cartNum) {
		sd.deleteCart(cartNum);
		
	}

	@Override
	public void orderInfo(OrdersVo order) {
		sd.orderInfo(order);
	}

	@Override
	public void orderInfo_Details(OrderDetailVo orderDetail) {
		sd.orderInfoDetail(orderDetail);
	}

	@Override
	public void cartAllDelete(String userId) {
		sd.cartAllDelete(userId);
	}

	@Override
	public List<OrdersVo> orderList(OrdersVo order) {
		List<OrdersVo> orderList = sd.orderList(order);
		return orderList;
	}

	@Override
	public List<OrdersVo> orderView(OrdersVo order) {
		List<OrdersVo> orderView = sd.orderView(order);
		return orderView;
	}

	@Override
	public void updateState(OrdersVo order) {
		sd.updateState(order);
		
	}

	@Override
	public List<OrdersVo> adminOrderList() {
		List<OrdersVo> adminOrderList = sd.adminOrderList();
		return adminOrderList;
	}

	@Override
	public List<OrdersVo> adminOrderView(OrdersVo order) {
		List<OrdersVo> adminOrderView = sd.adminOrderView(order);
		return adminOrderView;
	}

	@Override
	public void changeStock(BookVo book) {
		sd.changeStock(book);
	}

	@Override
	public void billUpdateState(OrdersVo order) {
		sd.billUpdateState(order);
	}

	@Override
	public List<OrdersVo> SearchOrderList(OrdersVo order) {
		List<OrdersVo> orderList = sd.searchOrderList(order);
		return orderList;
	}


	@Override
	public int processTotal() {
		int totProcessCnt = sd.processTotal();
		return totProcessCnt;
	}


}
