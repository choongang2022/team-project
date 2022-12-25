package com.oracle.choongangGroup.ry.model;

import java.util.Date;

import lombok.Data;

@Data
public class BookVo {
	/* 상품 id */
	private int bookId;
	
	/* 상품 이름 */
	private String bookName;
	
	/* 출판사 */
	private String publisher;
	
	/* 카테고리 코드 */
	private int cateCode;
	
	/* 카테고리 하위코드 */
	private int cateParent;
	
	/* 카테고리 하위코드 */
	private String cateName;
	
	/* 카테고리 하위코드 */
	private int tier;
	
	/* 상품 가격 */
	private int bookPrice;
	
	/* 상품 재고 */
	private int bookStock;
	
	/* 상품 소개 */
	private String bookInfo;
	
	/* 상품 이미지 */
	private String bookImg;
	
	/* 상품 경로 */
	private String uploadPath;
	
	/* 썸 네일 */
	private String bookThumbImg;
	
	/* 등록 날짜 */
	private Date regDate;
	
	private String type;
	private String keyword;
	
	
}
