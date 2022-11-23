#pragma once
#include "Types.h"

namespace nightshade{
	namespace Math {

		inline bool WorldToScreenCM(Vector3 pos, Vector2& screen, float matrix[16], int windowWidth, int windowHeight)
		{
			//Matrix-vector Product, multiplying world(eye) coordinates by projection matrix = clipCoords
			Vector4 clipCoords;
			clipCoords.x = pos.x * matrix[0] + pos.y * matrix[1] + pos.z * matrix[2] + matrix[3];
			clipCoords.y = pos.x * matrix[4] + pos.y * matrix[5] + pos.z * matrix[6] + matrix[7];
			clipCoords.z = pos.x * matrix[8] + pos.y * matrix[9] + pos.z * matrix[10] + matrix[11];
			clipCoords.w = pos.x * matrix[12] + pos.y * matrix[13] + pos.z * matrix[14] + matrix[15];

			if (clipCoords.w < 0.1f)
				return false;

			//perspective division, dividing by clip.W = Normalized Device Coordinates
			Vector3 NDC;
			NDC.x = clipCoords.x / clipCoords.w;
			NDC.y = clipCoords.y / clipCoords.w;
			NDC.z = clipCoords.z / clipCoords.w;

			screen.x = (windowWidth / 2 * NDC.x) + (NDC.x + windowWidth / 2);
			screen.y = -(windowHeight / 2 * NDC.y) + (NDC.y + windowHeight / 2);
			return true;
		}



		inline bool WorldToScreenRM(Vector3 pos, Vector2& screen, float matrix[16], int windowWidth, int windowHeight)
		{
			//Matrix-vector Product, multiplying world(eye) coordinates by projection matrix = clipCoords
			Vector4 clipCoords;
			clipCoords.x = pos.x * matrix[0] + pos.y * matrix[4] + pos.z * matrix[8] + matrix[12];
			clipCoords.y = pos.x * matrix[1] + pos.y * matrix[5] + pos.z * matrix[9] + matrix[13];
			clipCoords.z = pos.x * matrix[2] + pos.y * matrix[6] + pos.z * matrix[10] + matrix[14];
			clipCoords.w = pos.x * matrix[3] + pos.y * matrix[7] + pos.z * matrix[11] + matrix[15];

			if (clipCoords.w < 0.1f)
				return false;

			//perspective division, dividing by clip.W = Normalized Device Coordinates
			Vector3 NDC;
			NDC.x = clipCoords.x / clipCoords.w;
			NDC.y = clipCoords.y / clipCoords.w;
			NDC.z = clipCoords.z / clipCoords.w;

			//Transform to window coordinates
			screen.x = (windowWidth / 2 * NDC.x) + (NDC.x + windowWidth / 2);
			screen.y = -(windowHeight / 2 * NDC.y) + (NDC.y + windowHeight / 2);
			return true;
		}

	}
}