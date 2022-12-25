package com.oracle.choongangGroup.ry.dao;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.oracle.choongangGroup.ry.model.BookCartVo;
import com.oracle.choongangGroup.ry.model.BookVo;
import com.oracle.choongangGroup.ry.model.OrderDetailVo;
import com.oracle.choongangGroup.ry.model.OrdersVo;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Repository
public class ShopDaoImpl implements ShopDao {

	private final SqlSession session;

	@Override
	public List<BookVo> bookList() {
		List<BookVo> bookList = session.selectList("ShopList");
		return bookList;
	}

	@Override
	public BookVo detailBookList(int bookId) {
		BookVo book = new BookVo(); 
		book = session.selectOne("ShopDetailList", bookId);
		return book;
	}

	@Override
	public List<BookVo> searchList(BookVo book) {
		return session.selectList("SearchBookList", book);
	}

	@Override
	public void addCart(BookCartVo cart) {
		System.out.println("addCart => cart.getBookId() => "+cart.getBookId());
		System.out.println("addCart => cart.getUserId() => "+cart.getUserId());
		session.insert("AddCart", cart);
	}

	@Override
	public List<BookCartVo> bookCartList(String userId) {
		List<BookCartVo> cartList = session.selectList("CartList", userId);
		return cartList;
	}

	@Override
	public void deleteCart(int cartNum) {
		session.delete("DeleteCart", cartNum);
		
	}

	@Override
	public void orderInfo(OrdersVo order) {
		session.insert("OrderInfo", order);
	}

	@Override
	public void orderInfoDetail(OrderDetailVo orderDetail) {
		session.insert("OrderBookDetail", orderDetail);
		
	}

	@Override
	public void cartAllDelete(String userId) {
		session.delete("cartAllDelete", userId );
		
	}

	@Override
	public List<OrdersVo> orderList(OrdersVo order) {
		List<OrdersVo> orderList = session.selectList("OrderList", order);
		return orderList;
	}

	@Override
	public List<OrdersVo> orderView(OrdersVo order) {
		List<OrdersVo> orderView = session.selectList("OrderView", order);
		return orderView;
	}

	@Override
	public void updateState(OrdersVo order) {
		session.update("UpdateState", order);
	}

	@Override
	public List<OrdersVo> adminOrderList() {
		List<OrdersVo> adminOrderList = session.selectList("AdminOrderList");
		return adminOrderList;
	}

	@Override
	public List<OrdersVo> adminOrderView(OrdersVo order) {
		List<OrdersVo> adminOrderView = session.selectList("AdminOrderView", order);
		return adminOrderView;
	}

	@Override
	public void changeStock(BookVo book) {
		
		session.update("ChangeStock", book);
	}

	@Override
	public void billUpdateState(OrdersVo order) {
		session.update("BillUpdate", order);
	}

	@Override
	public List<OrdersVo> searchOrderList(OrdersVo order) {
		List<OrdersVo> orderList = session.selectList("SearchOrderList", order);
		return orderList;
	}

	
	
}
